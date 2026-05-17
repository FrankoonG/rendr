# 测试方法论

## 总原则

- **单路径基线优先**：composite test 通过 ≠ baseline 通过。永远先证明单路径下纯 rendr 不引入任何回归（吞吐、延迟、CPU），再做多路径
- **复现脚本是 commit 的一等公民**：任何 fix 必须附带"修复前必败、修复后必通"的脚本，进 `test/` 目录（已 gitignored）
- **真实带宽**：默认网络太快，限速到目标场景再测；不限速跑出来的 chaos 结果无意义
- **长驻才出真问题**：NAT 60s/120s 超时、conntrack 流失、内存累积——短测全无可见
- **混沌测试不可省**：每个 milestone 都有混沌门禁

## 测试环境形态

### 形态 A：单 VM 内 docker compose

最快迭代，3-5 个容器，模拟拓扑：

```
client ─── path1 ─── server
       └── path2 ─── server
       └── path3 ─── server
```

每个 path 是 docker network，可用 `docker network disconnect` 模拟链路死亡，可用 `tc netem` 在容器内加延迟/丢包/抖动。

**限速**：每条 path 上一个 `tc qdisc add ... tbf rate 50mbit` 之类的限速；不限速跑出来的 chaos 测试结果不可信。

**不能测什么**：容器内的虚拟网络不会真的有 NAT 表项过期、运营商策略 reset、移动网络切换基站。这些只能上 VM 或真机。

### 形态 B：多 VM 隔离

两台或更多 VM，VM 间走真实网络（同 VPC、跨地域、家宽-机房）。VM 内仍可起容器跑 rendr 实例。

适合验证：
- 真实 NAT 超时（VPC 之间或经 NAT 出口）
- TCP_REPAIR 在真实 conntrack 下的行为
- 跨 ISP 路径质量探测

### 形态 C：VM 内 nested 容器，加 tc/netem 制造可控劣化

形态 A + 系统性扰动。chaos harness 按预设时间表对每条 path 做：
- 完全断（disconnect / DROP）
- 延迟突增（300ms+）
- 抖动（50ms jitter）
- 丢包（5-30% loss）
- 带宽降级（50 Mbps → 5 Mbps）

每个 milestone 的 chaos 套件用一个 JSON / YAML 描述时间表，可重放、可 diff。

## 金标准测试（G1-G5）

详见 `docs/success-criteria.md`。每个 milestone 完成时必须跑、release 前必须跑。

测试实现要求：
- 每个 G\* 一个独立可执行（`test/g1_largefile.go` 等）
- 接受拓扑参数（path 数、限速、迁移触发时点）
- 输出：JSON 报告 + 终端摘要
- CI 友好（exit code = 0 / 非零）

## 混沌测试套件

基于 hy2scale `stream-rebind-chaos-test` 经验：

### 基本时间表

120 秒窗口，9 次断网，每次 2-10 秒，总断网 ≤ 60 秒。echo 间隔 2 秒，recv 超时 30 秒。

### 通过判据

| 指标 | 目标 |
|------|------|
| reconnects（应用层重连次数） | = 1（除初始连接外永不重连） |
| UP 期间到达率 | 单跳 ≥ 90%，多跳 ≥ 80% |
| max gap（单次 echo 最大间隔） | < 90 秒 |

### 实施

```bash
# 伪代码
for round in 1..10:
  reset_env()
  start_echo_loop(target, interval=2s)
  schedule = generate_random_chaos(9 disconnects, 2-10s each)
  apply_schedule(schedule)
  collect_metrics()
  assert reconnects==1, up_rate>=0.9, max_gap<90s
```

10 轮全部 PASS 才算"chaos test 通过"。

## TCP_REPAIR 专项测试（M2）

- kernel ≥ 4.5 检查
- CAP_NET_ADMIN 存在 / 缺失两种情况
- dump → restore 来回 1000 次，对端 wireshark 无 RST
- 不同 conntrack 状态下迁移行为
- timestamp / PAWS 下迁移
- 长连接 30 分钟 + 60 次迁移 + 0.1% 丢包阈值

## QUIC ConnID 迁移测试（M4）

- 客户端主动切 NIC：连接不断
- 服务端 NAT rebinding：连接不断
- 中间链路 NAT 表项失效 + 重建：连接不断
- 多 CID 池耗尽场景

## 长驻测试（NAT / 内存）

≥ 30 分钟连接保活，验证：

- NAT 60s / 120s / 300s / 30min 多个层级的超时点
- rendr 自身 goroutine / fd / 内存无累积
- bridge map 老旧条目能被 GC

跑法：连续运行 4 个测试实例，每个 30 min，错峰启动。结束后 `pprof` 拿 heap diff。

## 性能基线测试

每个 milestone 完成时跑：

| 指标 | 测试 |
|------|------|
| 吞吐（单连接） | iperf3 10 秒，记录 Gbps |
| 延迟（单连接） | ping over rendr Conn，1000 次，P50/P99 |
| 多连接吞吐 | 100 个并发连接每个 10MB |
| CPU 占用 | top -p \<pid\>，记录峰值 |
| RSS | smaps_rollup 取峰值 |

形成基线 JSON，后续 milestone 不能让任何指标退化 > 10%。

## Playwright / UI 测试

rendr 没有 UI。本节不适用。（hy2scale 的 dark-reader 测试条款仅针对 hy2scale repo。）

## 离线 / 不可达场景

- 所有路径同时死：超过 90 秒预算后必须 close（不能黑洞）
- 路径数为 0 启动：必须返回明确错误
- 路径数为 1 + 死亡：必须按"单路径死亡"语义处理，不能因"只有一个"就特殊处理

## 测试主机的获取方式

见 `docs/test-hosts.md`。
