# 来自 hy2scale 的工程经验（必读）

总结 hy2scale v1.3 网络韧性主干 12 个 commit 的实战结论。**这些不是设计建议而是反复回归后才稳定下来的硬规则**——违反会立即重现已知 bug。

## 1. 双层恢复模型

底层传输（QUIC / TCP / 其他）自己已经有重传 + 拥塞控制窗口。**不要在它上面再叠一层"几秒没动就 rebind"**，否则会和底层抢决策权、误杀慢速合法传输。

正确分工：
- 底层负责"短暂抖动"恢复（QUIC ~25s 内、TCP keepalive 内）
- rendr 负责"底层会话真死"后的迁移（25s+）
- 应用层永远不感知，除非超出迁移预算（默认 90s）

## 2. cleanClose 鉴别是核心

最大的坑：把**传输层故障**当成**应用层 EOF** 处理。一旦发生，"peer 抖一次，1 分钟内所有长连接全死"。

铁律：
- `io.EOF / io.ErrUnexpectedEOF / net.ErrClosed (来自本地 Close)` = 干净关闭，不触发迁移
- `quic.IdleTimeoutError / HandshakeTimeoutError / ApplicationError / TransportError` = 传输故障，**必须**触发迁移
- 这两类错误在 Go errors API 上极易混淆（QUIC 故障表面也是 `net.ErrClosed`），必须用 `errors.As` 显式分流

类似规则对将来的 TCP_REPAIR / gvisor 实现照样适用：内核回的 ETIMEDOUT/ECONNRESET 是传输故障，应用主动 close 不是。

## 3. 默认空触发器集

历史上加过"8s 单向静默就主动 rebind"——对慢速上传、Server-Sent-Events、低速下载全部误杀。最后默认就是**空触发器**，留接口供未来 path-quality 触发器使用，但默认不装任何东西。

新做法：触发器只允许由**外部观测**驱动（prime 模式下的质量分降级），不允许"看自身流量"做决策。

## 4. 自旋保护

迁移成功但没拿到任何 payload → 远端 bridge 大概率已被清理（短连接已结束的常见情况）→ 再迁移也是空转。最多 2 次无 payload 迁移就放弃。

加 30s cooldown 衰减：两次迁移间隔够长就重置计数器，避免长 peer reconnect 把额度烧掉。

## 5. 每跳独立迁移，不端到端

多跳路径里每一跳是独立的 rendr 实例。`A → B → C → D` 中 B↔C 断了，只有 B 和 C 的 bridge 进 suspended，A 和 D 完全无感。

**不要**实现端到端"我告诉对端要迁移"协议。复杂度爆炸、级联失败、没有任何额外收益。

## 6. 90s 迁移预算

混沌测试里反复验证下来：
- < 25s：底层自己恢复
- 25-90s：rendr 介入迁移，多数情况下能成
- \> 90s：放弃，把错误向上传播

90 这个数是 hy2scale 实测后稳定下来的，不要随手改。要改的话先回看 chaos test 数据。

## 7. countedConn 必须配对 close

替换底层 stream 时如果不 close 旧的 wrapper，每次迁移泄漏一个 conn-count。上游不稳定的节点上"active streams"会单调增长直到 panic。

通用化：任何对底层 fd / conn 的引用替换都必须**先关旧再装新**，不能反过来。

## 8. Bond 是 bug 工厂

hy2scale 的 bond.go 修了大概 10 个 commit 才稳定：

- teardown race（多路径同时收到 teardown 时去重）
- 死路径检测 vs 慢路径区分（5s read deadline）
- spin reorder（0.1ms × 动态迭代次数）
- path pinning（确保不同 path 走不同底层 QUIC client）
- reopen 时跳过已 teardown 的 path
- write deadline 检测 stuck

把这些当成 M8 / bond 必经的坑，不要以为可以一遍写完。**先把 prime + race 稳住再做 bond**。

## 9. 长驻测试的现实

NAT 60s、120s 超时只在长驻测试里暴露。短测全 PASS、上线一小时挂——hy2scale 干过好几次。

发布门禁里**必须**有 ≥30 分钟的长连接保活测试，不然 NAT 类问题不会被发现。

## 10. 带宽限速是 resilience 测试的必备前置

docker 内部网络是 ~25 Gbps，不限速跑的 chaos test 几乎所有"中途断网"窗口里数据都已经送完了，测不出"恢复后数据继续"。

每条路径强制限速到目标场景的实际带宽（家用 50-200 Mbps、移动 10-30 Mbps），结论才有意义。

## 11. DNS 污染只能在污染环境里测

`root@172.20.0.107` 这种**真实运营商 DNS 污染**的主机，对验证 DNS 相关功能是必备的。Singapore demo cluster 自己没 DNS 污染，怎么造都造不出。

类比到 rendr：路径质量退化的测试只能在能真的丢包、抖动、断开的链路上做，不能纯靠 tc netem 模拟（tc netem 测不出 conntrack / NAT 表项过期带来的迁移失败）。

## 12. 不要直接更新生产节点验证

hy2scale 历史上几次"在 demo 测过了就推 prod"的更新出问题。流程必须是：

1. demo compose 复现 bug
2. demo compose 验证 fix
3. 单台 staging 长驻 30+ 分钟
4. 才推 prod

rendr 没有自己的"生产节点"，但任何上层应用（hy2scale、xray、未来的接入方）必须有等价的"先 staging 长驻再推" 纪律。

## 13. 复现 → 修复 → 回归 三步缺一不可

很多 hy2scale 历史 PR 是：症状描述 → 改代码 → "看起来好了"。结果回归率 30%+。

强制：每个 fix commit 必须附复现脚本（进 `test/`），脚本能在干净环境跑出"修复前必败、修复后必通"两个结果。
