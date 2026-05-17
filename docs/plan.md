# rendr 实施计划

## 设计原则

按"能否单独证明价值"切里程碑。每个 milestone 完成时必须有一个**可独立 demo 的能力**。

最终目标：**G1-G5 全部通过的 xray transport**。在这一目标达成之前，路线、方案、API 都允许推翻重做。**不允许"差不多就行"地往下推进**。

## 迭代纪律（硬约束）

每个 milestone 的实施按这个循环：

```
设计 → 实现 → 跑 G1-G5 → 失败 → 分析根因 → 换方案 → 重跑
                                                   ↑
                                                   └── 循环直到金标准达成
```

如果三次方案换下来仍未通过，必须回头修订更上游的设计（比如"双端模型"换"单端 TCP_REPAIR"），而不是继续在原方案上小修。

## M0 — 接口与协议冻结

**交付**：
- `Conn` / `PacketConn` 公共 API（实现 net.Conn / net.PacketConn）
- 路径抽象 `Path` + 质量指标接口
- 控制平面线协议 v0：HELLO / MIGRATE_NOTIFY / PATH_QUALITY / HEARTBEAT / BYE / BRIDGE_TAG
- 模式枚举：prime / bond / race
- xray 接入草案：rendr 作为 xray transport 的 protobuf stream settings 形态（见 `docs/xray-integration.md`）

不需要可运行实现。本 milestone 交付接口 + 协议字节布局 + 一份 xray 兼容性自检清单。

**完成判据**：能讨论"如果跑 G1，每一层会发生什么"全流程，无未解决疑点。

## M1 — 双端 TCP 终结 + 用户态 bridge

**目标**：用 hy2scale streamBridge 模型证明引擎可行，跑通 G1-G5（在双端 rendr 拓扑下）。

**实现**：
- 应用 fd = rendr 提供的 unix socket / loopback
- 内部 path = TCP byte stream，可替换
- 90s 迁移预算、zombie 保护、cleanClose 鉴别

**测试**：
- G1 大文件传输（≥1 GB），迁移 3 次，零中断、SHA-256 一致
- G2 30 min echo，30 次迁移，0 丢失
- G4 path 强杀 + G5 path 回归
- chaos 套件 10/10 PASS

**判退**：如果 G1 在 10 次重试内无法稳定通过，分析根因，转 M1' 或暂缓上 M2。

## M2 — QUIC 路径 + QUIC ConnID 迁移

**目标**：path 类型从 TCP 扩展到 QUIC，并验证 RFC 9000 §9 ConnID 迁移可被 rendr 触发。

**实现**：
- QUIC transport adapter（quic-go）
- 单条 QUIC 连接 = 一个 path
- rendr 决定切 path 时调用 quic-go 的 migration API
- 与 M1 的 TCP path 在引擎层完全等价

**测试**：
- G3 100k pps QUIC 单连接 + 10 次 ConnID 迁移
- G1 + G2 在 QUIC path 上也跑通
- 混合拓扑（path A = TCP，path B = QUIC）下 G1-G5

**判退**：quic-go 的迁移 API 表现不稳时，spike mvfst / quiche FFI 评估，但首选还是 quic-go。

## M3 — TCP_REPAIR 单端迁移（spike + 决定）

**目标**：评估方案 B 是否值得做。

**步骤**：
1. 在 demo VM 上做最小 POC：单机内把已建立连接的承载从 socket A 搬到 socket B，对端不感知 RST
2. 在 docker 容器内（带 CAP_NET_ADMIN）验证可行
3. 容器内 conntrack 行为评估
4. 失败 → 走 M4

**判退条件**：POC 跑不通就转 M4。**不浪费时间在不可行的实现路径上**。

## M4 — gvisor netstack 用户态 TCP（M3 fallback）

**前置**：M3 决定不投入或失败。

**目标**：单端透明迁移的跨平台兜底。

**实现**：
- gvisor `pkg/tcpip` 嵌入
- TCB 序列化 / 反序列化
- 用户态 TCP endpoint 在 path 切换时不感知

**测试**：等同 M3 的 acceptance（即使 M3 跳过，M4 验收标准独立）。

## M5 — 不透明 UDP flow-id 迁移

**前置**：M2 通过。

**目标**：非 QUIC UDP 协议（WireGuard echo / 自定义 UDP）的迁移。

**实现**：
- 8 字节 flow-id 头
- 双端 rendr 时的完全可控迁移
- 单端 rendr 的 SNAT 出口模式

**测试**：
- WireGuard 隧道 over rendr，UDP echo 不感知 path 切换
- 高包率（100k pps）下 dedup 无溢出
- 60+ min NAT keepalive 长驻

## M6 — prime 模式

**前置**：M1 + M2（M3 / M4 不阻塞）。

**目标**：基于质量分自动选 path + 退化时主动迁移。

**实现**：
- 持续 rtt / jitter / loss 探测
- 综合分 `score = rtt + α·jitter + β·loss`
- hysteresis / dwell / cooldown 三旋钮
- 默认参数：hysteresis=0.25, dwell=5s, cooldown=30s

**测试**：
- 模拟"两条 path 周期性互换好坏"，prime 应跟随最优
- 应用观测的 RTT 应稳定在最优 path 水平
- 迁移次数 ≈ 实际好坏切换次数

## M7 — race 模式

**前置**：M1 + M2。

**目标**：每帧多 path 并发 + 接收端 dedup。

**测试**：
- 单 path 30% loss + 单 path 100ms 延迟，race 下应用观测 0 loss + ~0 多余延迟
- dedup 窗口溢出检测
- 带宽 = 单 path 上限（race 是冗余，不是聚合）

## M8 — bond 模式

**前置**：M6 稳定。

**警告**：hy2scale 经验 bond 是 bug 工厂。预算给足，不要硬塞排期。

**目标**：
- 多 path 帧级聚合
- 单 path 死亡 → redistribute → 路径恢复 → 重新加入

**测试**：
- 两条 50 Mbps 聚合到 ~100 Mbps
- 杀一条降到 50，恢复回 100，过程中无应用层错误
- teardown 双向通知正确性

## M9 — xray 集成

**前置**：M1 + M2 + M6 + M7 通过 G1-G5。

**目标**：rendr 作为 xray transport 接入，xray 自带协议（vmess/vless/trojan/ss）over rendr over (tcp+quic+...) 跑通。

**实现细节**：见 `docs/xray-integration.md`，按 X1-X7 分子阶段。

**测试**：
- xray 自己的回归测试套件 over rendr
- G1-G5 在 xray 集成形态下重跑（不能因为多了一层就失分）

## M10 — 参考 demo：基于 rendr 的 SOCKS5

最小可读的完整 example。给上层开发者一个嵌入示范。**不算独立 milestone，作为 docs / example 维护**。

## 路线之外

- 与 hy2scale 集成：让 hy2scale 把 streamBridge 替换成 rendr，是 hy2scale 侧的工作，不在 rendr repo 做
- multipath QUIC（IETF draft）：纳入观察，目前不基于它构建
