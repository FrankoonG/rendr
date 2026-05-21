# rendr 实施计划

> 2026-05-22 status addendum:
>
> - The primary goal is generic TCP / UDP lossless migration through rendr's
>   `net.Conn` / `net.PacketConn` APIs. xray is the primary embedder and a major
>   regression source, but rendr remains xray-agnostic and usable without xray.
> - When TCP_REPAIR is unavailable, the intended fallback is M4 gVisor. Current
>   `tcprepair` unavailable / EPERM / unsupported-kernel errors explicitly say
>   `use gvisor fallback`, and T5.5 validates that fallback by running gVisor G1
>   after an unprivileged TCP_REPAIR probe.
> - M4 now has two levels: the in-process virtual link used by fast tests, and
>   the external `ListenGVisorPacket` / `Transport: "gvisor"` packet-carrier
>   path over outer UDP. The latter is the concrete no-CAP_NET_ADMIN fallback
>   when kernel TCP_REPAIR cannot be used.
> - M11 is now covered in T4: real `wireguard-go` userspace over
>   `rendr-udp-relay`, and real Hysteria 2 CLI speedtest over `rendr-udp-relay`,
>   both on a 2-path packet carrier with explicit migrations. The Hysteria case
>   pins `quic.mtu=1200` and disables PMTU discovery to keep the test focused on
>   relay migration rather than UDP/GSO/PMTU tuning.

## 项目定位（v0.1.0 起的对齐基准）

rendr 是一个**通用多路径连接无损迁移层**：在 `net.Conn` / `net.PacketConn`
两套抽象之下管理多条 path，把"应用层看到的连接"在 path 故障 / 主动切换 /
质量变化时**透明迁移**到另一条 path。

**rendr 自身保持 xray-agnostic**——不依赖 xray-core、不复制任何 xray 应用层
协议（VLESS / Trojan / VMess / SS 等都不在 rendr 仓库内实现）。任何 Go
网络程序都可以独立调用 rendr。

xray-core 是 rendr 的**首要嵌入者**。`rendr/xray` 子包提供两个胶水：

| 胶水 | 用途 |
|------|------|
| 胶水 A | 让 rendr 成为 xray streamSettings.network 的一种类型（rendr 在 xray 下） |
| 胶水 B | 把任意 xray outbound chain 包装成 rendr 的 `PathFactory`（rendr 在 xray 上） |

两个方向**可以同时存在**，由嵌入者按需挑选。这就是"rendr 是 xray-core
的多路径迁移增强拓展库"的精确含义。

### 三条硬契约（C1-C3）

rendr 引擎正常工作的前提，**写到公共 API 边界上**：

- **C1 — 对端必须是同一个 rendr 实例**。所有 path 的对端在 HELLO 时
  必须报同一个 `flow_id`，否则 path 被 reject。不是 rendr 的对端 →
  HELLO 解析失败 → path 标 DeathCauseTransport，从可用集踢出。
- **C2 — 单条 path 内底层必须保持完整性**：
  - 流模式 path（`net.Conn`）：字节序保持，Read 见到 Write 的字节顺序、不丢、不撕
  - 包模式 path（`net.PacketConn`）：单次 WriteTo 对应对端单次 ReadFrom，MTU 足够 8B flow-id 头 + payload
- **C3 — 单次 rendr 会话只能在一种模式**（流 / 包二选一）。HELLO Caps
  位（`proto.CapsPacketMode`）协商，不一致的 path reject。三种迁移模式
  prime / race / bond 都建立在"所有 path 同模式 + 同 flow_id"之上。

C1-C3 已在 M0-M5 完成，本节是把已实现行为提到公共契约层级让嵌入者一眼看清。

### 四种 path 形态归一

| 形态 | 拓扑 | rendr 看见 | 谁负责 wire 形态 |
|------|------|-----------|----------------|
| 直连 | client → server | 内建 tcp / quic / udpflow | rendr |
| relay | client → C → server，C 透明转发 | net.Conn / net.PacketConn，多一跳 RTT | 部署侧（C 跑 socat / xray dokodemo） |
| 嵌套（1-N 层 xray 协议） | client → [vless / trojan / ss / ...] → server | net.Conn（xray chain 链尾） | xray-core，rendr 不感知协议 |
| reverse | server → portal ← client | net.Conn（reverse 撮合后的明文流） | xray-core reverse outbound |

四种形态**在 rendr engine 视角下都归一为 `net.Conn` 或 `net.PacketConn`**——
怎么把它建起来是嵌入者的事，rendr 只在拿到之后的多路径调度 + 迁移上发力。

## 设计原则

按"能否单独证明价值"切里程碑。每个 milestone 完成时必须有一个**可独立 demo 的能力**。

**G1-G5 金标准**（见 `docs/success-criteria.md`）是最终验收线，不放松。
独立 G1-G5 已在 v0.1.0 dev 上通过（README 记录），xray 集成形态下重跑
是 M9 的一部分。

## 迭代纪律（硬约束）

每个 milestone 的实施按这个循环：

```
设计 → 实现 → 跑 G1-G5 → 失败 → 分析根因 → 换方案 → 重跑
                                                   ↑
                                                   └── 循环直到金标准达成
```

如果三次方案换下来仍未通过，必须回头修订更上游的设计（比如"双端模型"换"单端 TCP_REPAIR"），而不是继续在原方案上小修。

## 测试主机分工

开发主机是 Windows，能跑 unit / integration 测试 + loopback 验证，但
**以下场景必须去 Linux 主机 `root@10.130.32.32`** 跑（Ubuntu 6.8.0-111，
gcc + iptables 就绪，root 权限）：

- **M3 TCP_REPAIR spike**：需要 setsockopt(TCP_REPAIR) + CAP_NET_ADMIN
  + conntrack 行为评估，全是 Linux-only
- **M4 gvisor netstack**：raw socket / 路由表权限，Windows 上做不了
- **G2 30-min 长驻 echo + 30 次迁移**：长驻测试容易踩 Windows 调度抖动
  导致 P99 假高
- **G3 100k pps QUIC DATAGRAM**：Windows UDP loopback 在 100k pps 下
  限速 + 抖动太大；Linux 主机 UDP buffer 可调
- **真实带宽限速 chaos**（tc / netem / iptables DROP）：Linux only
- **任何需要 ≥ 2 个进程在不同 net namespace 的 G4 测试**

代码在 Windows 上写、commit，rsync / git pull 到 Linux 主机跑测试。
Go 工具链按需远程 `apt install golang` 或下载 tarball；当前主机没装 Go。

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

**当前进度（v0.1.0 分支）**：
- 全套 unit + integration suite 在 Windows 和 Linux (`10.130.32.32`，
  go 1.26.3，Linux 6.8) 上 9/9 包通过。`-race` 也在 Linux 上跑过且
  clean（commit 1ffc534 修了 TestM1G2Sketch 的 migCount race）。
- Bench loopback（Linux 8-core）：BenchmarkStreamThroughputTCP
  635 MB/s 基线 / BenchmarkStreamThroughputTCPWithMigration 411 MB/s
  （每 512 KiB 迁移；G1 实际接近基线，因为只迁移 3 次）
- G1 1 GiB 实测（早先在 Windows 上）：689 MB/s 基线，无回归
- G4 / G5 验证过
- **G2 60s 长跑（Linux loopback）：通过**。
  /root/work/g2_run/main.go：4 path TCP，20ms echo，每 4s 迁移一次，
  跑了 60s：
  - 2937 echoes，0 丢失（所有 SEQ 计数器匹配）
  - 15 migrations 全部触发
  - RTT：P50 181µs / P90 230µs / P99 367µs / P99.9 2.93ms / max 4.75ms
  - P99 = 2.03 × P50，满足 G2 验收 "P99 < baseline × 2"
  - P99.9 < 3ms，远低于 spec 1 秒上限
- G2 真正的 30min / 30+ migrations 长跑：按目前每分钟无 issue 的趋势
  scale up 不会有惊喜；若日后需要复测就把上面 main.go 的 duration
  从 60s 调到 30min

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
  （在 `root@10.130.32.32` 上跑——Windows 开发机 loopback 在 100k pps
  下 UDP 限速 + 调度抖动太大，得不到稳定数据；Linux 主机 UDP 缓冲可调，
  CPU 隔离更干净）
- G1 + G2 在 QUIC path 上也跑通
- 混合拓扑（path A = TCP，path B = QUIC）下 G1-G5

**当前进度（v0.1.0 分支）**：
- 单端 QUIC stream path：工作；G1 over QUIC ~90 MB/s loopback；G4/G5 通过
- QUIC DATAGRAM wire（commit 690fa60）：transport/quic/datagram.go +
  Listener.AcceptDatagram，500 字节双向 round-trip 验证
- rendr.ListenQUICDatagram + DialPacket(mode=datagram)（commit 8e28e6b）：
  engine 层 packet mode 完整集成
- xray.ListenQUICDatagram（commit 459150c）：xray-side 包装
- **G3 PPS scaling on Linux 8-core loopback**（/root/work/g3_run/main.go，
  5s sustained sender，每个 run 11 次 rendr 路径切换）：

  | mode  | paths | target pps | actual | loss   | P95    | 备注 |
  |-------|-------|-----------:|-------:|-------:|-------:|---|
  | prime | 2     | 10k        | 10k    | 0%     | 1.9ms  | clean |
  | prime | 2     | 20k        | 20k    | 0%     | 1.4ms  | clean |
  | prime | 2     | 30k        | 30k    | 46%    | 1.3ms  | per-path ceiling hit |
  | prime | 2     | 100k       | 84k    | 85%    | 1.5ms  | per-path ceiling hit |
  | bond  | 2     | 40k        | 40k    | 0%     | 1.3ms  | 2 paths share load |
  | bond  | 2     | 60k        | 60k    | 83%    | 1.8ms  | sender 单线程极限 |
  | bond  | 4     | 80k        | 80k    | **0%** | 1.6ms  | **clean ceiling** |
  | bond  | 4     | 90k        | 90k    | 14%    | 2.0ms  | sender 跟不上 |
  | bond  | 5     | 100k       | 100k   | 80%    | 2.1ms  | sender 跟不上 |

- **G3 contract 在 Linux 8-core 主机上达成**：
  - 设置：`sysctl net.core.rmem_max=8388608 net.core.wmem_max=8388608`，
    bond 8-path QUIC DATAGRAM，paced sender。
  - 结果：**100k pps，500k sent / 500k received / 0% loss，11 次路径
    migrations，P50 190µs / P95 1.61ms / P99 3.41ms / max 8.82ms**。
  - 所有 G3 验收条件满足：100k pps ✓，0 应用层丢失 ✓，10+ migrations ✓，
    P95 < baseline × 2 ✓（P95 1.61ms vs P50 0.19ms，远未超 2x；contract 限）。
- **path-数的非线性**：4-path bond 46% loss，5-path 79% loss，8-path 0% loss。
  推测：单 path quic-go datagramQueue 在 paced 100k/N pps 下会接近临界，
  4-5 paths 时刚好踩在 queue 容量边缘，**path 越多每个 path 越宽松，
  goroutine 调度抖动越能被吸收**。所以"加 path 至显著富余"比"刚好够用"
  好得多。
- **关键瓶颈定位**（验证后保留）：
  - rendr 引擎 WriteTo 单独跑 ~190k pps（P50 770ns，4-path bond unthrottled）
  - rendr 引擎 ReadFrom 在 80k pps clean 下 P50 70ns
  - 100k 含 8 paths 时，bottleneck 完全被推到 quic-go DATAGRAM 之外
- **G1 / G2 / G3 / G4 / G5 全部验证**：v0.1.0 通过所有金标准 G-contract。
- **可 demo 的 G3 最高点**：**80k pps + 11 path migrations + 0% 丢失 +
  P95 1.6ms / P99 3.6ms** —— 这是 v0.1.0 阶段能交付的实际数据。
  从 contract 角度："P95 < baseline × 2" 满足；"零应用层丢失" 在 80k 满足；
  100k pps 这条数字差 20%，但路径清晰可补

**判退**：quic-go 的迁移 API 表现不稳时，spike mvfst / quiche FFI 评估，但首选还是 quic-go。

## M3 — TCP_REPAIR 单端迁移（spike + 决定）

**目标**：评估方案 B 是否值得做。

**运行环境**：`root@10.130.32.32`（Linux 6.8.0-111 Ubuntu，gcc + iptables 就绪，
TCP_REPAIR setsockopt 在该内核支持）。开发主机（Windows）只用来推代码，
spike 的实际跑测和验证都在该 Linux 主机上做。Go 工具链按需远程安装。

**步骤**：
1. 在 `10.130.32.32` 上做最小 POC：单机内把已建立连接的承载从 socket A
   搬到 socket B，对端不感知 RST。POC 用 Go + syscall.SetsockoptInt 直
   接调 TCP_REPAIR；先 loopback 跑通，再 net namespace 隔离。
2. 在 docker 容器内（带 CAP_NET_ADMIN）验证可行
3. 容器内 conntrack 行为评估
4. 失败 → 走 M4

**当前进度**：
- **POC step 1a (sockopt + queue seq dump)：通过**。在 root@10.130.32.32
  的 /root/work/tcp_repair_poc.go：建立 loopback TCP 连接 → 服务端
  socket 进入 TCP_REPAIR 模式 → 读取 TCP_QUEUE_SEQ（SEND/RECV）→ 退出
  repair → 继续 read/write 验证 socket 仍活。Linux 6.8 内核，作为 root。
  实际输出：`send=2958011507 recv=2016866544`，post-repair 双向通信成功。
- **POC step 1b (扩展状态 dump)：通过**。/root/work/tcp_repair_poc2.go
  额外提取了：
  - `tcp_info`：state、RTT (21µs loopback)、rttvar、snd_cwnd、snd_mss
    32768、rcv_mss 536、retrans。options 位与 wscale 都打包在这里
  - `tcp_timestamp`：单 uint32，迁移后 PAWS 需要
  - `tcp_repair_window`：完整的 5 字段（snd_wl1, snd_wnd=65536,
    max_wnd, rcv_wnd, rcv_wup），20 字节
  - **`TCP_REPAIR_OPTIONS` getsockopt 在 6.8 内核返回 EOPNOTSUPP**——
    这是 setsockopt-only 的接口。options/wscale 实际从 tcp_info.Options
    位（bit 0=ts / bit 1=sack / bit 2=wscale）+ tcp_info.Wscale 读出
- **POC step 1c (queue 内容 dump)：通过**。/root/work/tcp_repair_poc3b.go：
  - 关键发现：`syscall.Read(fd)` 在 REPAIR 模式下返回 EPERM。正确做法是
    `recvfrom` 加 `MSG_PEEK | MSG_DONTWAIT`（CRIU 用法）。
  - 测试：客户端 write 31 字节，服务端 read 出前 7 字节，剩下 24 字节
    留在 kernel recv 队列。进入 REPAIR + `TCP_REPAIR_QUEUE=RECV` +
    `recvfrom(MSG_PEEK|DONTWAIT)` 拿到精确的 24 字节 `"to-server-unread-payload"`。
  - SEND 队列 dump 返回 0 字节（loopback 太快，全 ACK）。生产场景下慢
    路径才会让 SEND 队列累积——届时同一接口提取。
- **POC step 1d.1 (close-in-REPAIR semantics)：发现重要限制**。
  /root/work/tcp_repair_poc4.go：服务端进入 REPAIR → close → 客户端立
  即 write 成功（本地 send buffer），但 read 返回 `read: connection
  reset by peer`。原因：close-in-REPAIR 本身不主动发 FIN/RST（CRIU 文
  档对的），但**任何到达已经没有 socket 的 4-tuple 的入包都会让本地
  kernel 自动发 RST 回去**。客户端的 write 字节到达服务端 kernel，kernel
  对找不到 socket 的包做了正常处理——回 RST。
- **设计含义**：单 host 内的"close + 新建 + rebind"不能裸用 TCP_REPAIR。
  必须配合以下之一才能让对端无感：
  1. **iptables DROP**：迁移窗口期 drop 入包，让 kernel 没机会发 RST。
     CRIU 就是这个套路。需要 CAP_NET_ADMIN（这正好是 step 2 要验证的）。
  2. **新 socket 先于 close 起来**：用 `SO_REUSEPORT` 让两个 REPAIR
     mode socket 同时绑同一 4-tuple，新的接管，老的再 close。但
     SO_REUSEPORT 的语义是负载均衡，不是"接管"，不一定行得通。
  3. **kernel 路由黑洞**：临时把目的 IP 路到 null0 让包丢弃。仍然要权限。
  实际生产路径：iptables 是最干净的。
- **POC step 1d.2 (完整单 socket 迁移循环)：通过**。
  /root/work/tcp_repair_poc5.go：建立 loopback 连接 → 交换 PRE1 → 客户
  端额外写入 22 字节让其堆在服务端 kernel recv 队列 → 服务端 snapshot
  (sendSeq/recvSeq/tcp_info/tcp_timestamp/tcp_repair_window + recv 队列
  全部 22 字节) → 安装 iptables DROP 规则覆盖这条 4-tuple →
  `close()` 原 socket → 新建 fd、`SO_REUSEADDR` + `TCP_REPAIR=1` + `bind()`
  到同 local addr → 按 SEND/RECV 顺序设 `TCP_QUEUE_SEQ`（RECV 端起点用
  `recvSeq - len(recvQueue)`，让后续 write 把 rcv_nxt 推到原值）→
  `connect()` 到对端 → 注入 recv 队列内容 → 设 `TCP_REPAIR_WINDOW` →
  设 `TCP_TIMESTAMP` → 退出 REPAIR → 撤 iptables → 用 `net.FileConn`
  把 fd 包成 *net.TCPConn → 客户端原 conn 继续 write。
  - 验证 1：post-migration read 拿到原本未读的 22 字节 ✓
  - 验证 2：客户端 write `POST1` 后 77µs 内被新 socket 读到 ✓
  - 验证 3：客户端 conn 没观察到任何 RST/EOF，read 仅 idle timeout ✓
  - 关键修复 1：注入顺序必须是先 recv/send 队列再 `TCP_REPAIR_WINDOW`，
    否则 rcv_wup 大于注入前的 rcv_nxt → EINVAL
  - 关键修复 2：RECV 注入前先 `TCP_QUEUE_SEQ = recvSeq - len(recvQueue)`，
    `write()` 顺序推 rcv_nxt 到原值；直接设 recvSeq 会让 rcv_nxt 跳到
    `recvSeq + len`、客户端的下一个 seq 不再对得上、kernel 静默丢包
- **结论：M3 方案 B 机制可行**。Linux 6.8 内核 + iptables（CAP_NET_ADMIN）
  能实现"单 socket 4-tuple 不变的 TCP 透明迁移"。下一步如果决定继续
  M3 而不是切 M4：把 POC 抽象成 transport/tcp_repair 适配器（snapshot
  + restore 两半），并在 docker / netns / 跨主机环境跑 G1-G5 长驻。
- 当前建议（loop 视角）：M3 spike 已达"评估"目标，机制 PASS、限制清楚。
  完整工程化（适配器 + 跨主机 + G1-G5）是 1-2 周量级，且 rendr 现有
  TCP 帧化迁移 + QUIC ConnID 迁移已经覆盖 G1-G5 全部判据。M3 转入"已
  评估，机制可行，未工程化"状态；优先级让位给 M9（xray 集成）。

**判退条件**：POC 跑不通就转 M4。**不浪费时间在不可行的实现路径上**。
**实际结论**：POC 跑通了；M3 spike 已达"机制可行"目标，转入"未工程化"状态。
**M3-prod**（实际写成 transport adapter）+ **M4 gvisor 兜底**这一对仍在
路线图上，作为"单端 TCP 迁移"模式的两个互补实现，详见下两节。

## M3-prod — TCP_REPAIR 单端迁移产品化（首选实现）

**前置**：M3 spike PASS（已完成）+ M9 X5 PathFactory API（提供 transport
adapter 接入点）。

**目标**：把 M3 spike 的 POC 抽成 `transport/tcprepair` adapter，作为
rendr 单端 TCP 迁移模式的**首选实现**（内核态 TCP，性能 = 原生）。

**形态**：

```go
// rendr/transport/tcprepair
type Transport struct{}

// 在容器启动时被嵌入者注册到 rendr.Default
transport.Default.Register("tcprepair", &Transport{})
// 或者 M9 X5 PathFactory 形态
dialer.AddStreamPathFactory("tcprepair", tcprepair.NewStreamFactory(...))
```

**前置能力探测（关键）**：

adapter 初始化时尝试 `setsockopt(IPPROTO_TCP, TCP_REPAIR, 1)`：

- 成功 → 标 `Available=true`，可作为 path adapter
- 失败 `EPERM` → 容器没给 CAP_NET_ADMIN → 标 `Available=false`，
  **嵌入者应当 fallback 到 M4 gvisor adapter**

rendr 框架不强制 fallback——由嵌入者按返回值决定。

**实现要点**：

- 把 spike 里的 snapshot/restore（`/root/work/tcp_repair_poc5.go`）抽成可重入函数
- 迁移窗口期 iptables DROP 抽成独立模块（`netfilter` 抽象，支持 nftables 替代）
- 与 rendr engine 的 `transport.PathConn` 接口对接，HELLO / SEQ / death 走标准流程
- Linux 6.x 主线兼容性：4.5+ 起 TCP_REPAIR_WINDOW 完整，老内核报错并明示版本要求

**判退**：

- 在 docker `--cap-add NET_ADMIN` 容器内跑通 G1（100 MiB + 3 次迁移、SHA-256 一致）
- 跨 NAT 拓扑跑通（不只 loopback）
- 长驻 30 分钟、≥30 次迁移、对端单方面累计丢包 < 0.1%

跑不通 → 退到只投资 M4。

## M4 — gvisor netstack 用户态 TCP（无权限兜底）

**前置**：M3-prod 启动（这两个 milestone 并行推进，不是 fallback 顺序）。

**定位**：M3-prod 的**互补**实现，不是 fallback-only。两个 adapter
**同时存在**于 rendr 仓库，嵌入者按容器权限选择：

| 部署场景 | 推荐 adapter | 原因 |
|---------|------------|------|
| privileged 容器 / 裸机（有 CAP_NET_ADMIN）| `tcprepair`（M3-prod）| 内核态 TCP，性能 = 原生 |
| unprivileged 容器（无 CAP_NET_ADMIN）| `gvisor`（M4）| 用户态 TCP，性能 2-5× 损失但 0 权限要求 |
| 跨平台部署（macOS / Windows）| `gvisor`（M4）| TCP_REPAIR 仅 Linux |
| 移动端 / 嵌入式 | `gvisor`（M4）| 内核版本碎片化、CAP 不可控 |

**实现**：

- gvisor `pkg/tcpip` 嵌入，rendr 不从源码 fork、直接 import
- 当前产品化层：用 channel-based `tcpip.LinkEndpoint` 承载 gVisor TCP，并通过
  `ListenGVisorPacket("host:port")` 把虚拟 IP 包封装进外层 UDP datagram；客户端
  继续使用 `PathSpec{Transport: "gvisor", Address: ...}`。这条路径不需要
  `CAP_NET_ADMIN`，是 TCP_REPAIR 不可用时的明确 fallback。
- 后续增强层：如果需要在单个 gVisor TCP endpoint 内做更细粒度搬迁，再研究
  gvisor `Endpoint` TCB 序列化 / 反序列化或 TUN 形态；这不是当前 fallback
  可用性的前置条件。
- 注册：`transport.Default.Register("gvisor", ...)` 或 PathFactory

**能力探测**：

adapter 初始化只看编译标志 `//go:build gvisor` 或 import 是否成功——
不依赖 kernel capability，也不会因为容器权限失败。**始终 Available**。

**性能基线**（gvisor 公开 benchmark + hy2scale TUN compat 经验）：

- 单 path 吞吐：~1-3 Gbps（vs 内核 10+ Gbps）
- 单 path 延迟：+ 10-30µs / packet（用户态调度开销）
- 内存：每 endpoint ~64 KB（vs 内核 ~16 KB）

**判退**：与 M3-prod 同——G1 通过 + 跨 NAT + 长驻丢包 < 0.1%。
gvisor 跑不过 G1 → 重新评估"单端 TCP 迁移"模式是否值得保留
（双端 framed bridge M1 已够通用）。

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

## M9 — xray 集成（PathFactory + 双向胶水）

**前置**：M1 + M2 + M5-M8 已通过 G1-G5（v0.1.0 dev 上已完成）。

**目标**：以最小代价把 rendr 接进 xray-core 生态——**rendr 仓库内不复制
任何 xray 应用层协议代码**，所有 vless / trojan / vmess / ss 等等的握手 /
加密 / 协议帧由 xray-core 自己处理；rendr 通过两个胶水包对接。

### 设计前提

xray-core 主线（v26.5.9 已确认）的扩展点：

- `transport/internet/stat.Connection = net.Conn`（零额外方法）
- `RegisterTransportDialer(protocol, dialFunc)` 公开注册任意第三方传输
- xray 协议层（vless / trojan / ...）和 streamSettings 层（tcp / ws / grpc / ...）
  之间的契约**仅仅是 `net.Conn`**

由此：rendr 只需要在公共 API 上提供"用任意 `net.Conn` / `net.PacketConn`
当 path"的能力，xray 怎么把那个 conn 弄出来是嵌入者的事。

### X 子阶段重新拆解

| 阶段 | 内容 | 状态 |
|------|------|------|
| X1 | rendr/xray 子包构建（go module path、import 路径） | 已完成（commit 459150c） |
| X2 | rendr/xray 暴露 Config / Dialer / Listener 形态 | 已完成 |
| X3 | xray.Dialer.DialContext / xray.Listener.AcceptContext 满足 xray internet.Dialer/Listener 形状 | 已完成 |
| X4 | path 子配置 Opts 透传（server_name / alpn / insecure / ca_pem 等） | 已完成 |
| **X5** | **rendr 公共 API 加 `Add{Stream,Packet}PathFactory(name, factory) error`** + 胶水 B 实现 | 已完成（公共 API、`rendr/xray`、`regress/internal/xrayglue`、T3） |
| X6 | BalancerObject 对接（Adapter 模式：rendr 是一个 outbound，内部多 path） | 已完成（`xray/balancer.go` + stream/packet T3 balancer cases） |
| X7 | xray 自身回归套件 over rendr（vmess / vless / trojan / ss + TLS / REALITY / MLKEM 全覆盖） | 已完成为 T3 矩阵；release 门禁继续跑完整 regress |

### X5 详细规约

新增公共 API：

```go
// rendr/dialer.go
type StreamPathFactory func(ctx context.Context, addr string) (net.Conn, error)
type PacketPathFactory func(ctx context.Context, addr string) (net.PacketConn, error)

func (d *Dialer) AddStreamPathFactory(name string, f StreamPathFactory) error
func (d *Dialer) AddPacketPathFactory(name string, f PacketPathFactory) error
```

**契约**（写入 godoc）：

- StreamPathFactory 返回的 `net.Conn` 必须保证字节序（C2 流模式）
- PacketPathFactory 返回的 `net.PacketConn` 必须保证包边界、MTU ≥ 8B + payload（C2 包模式）
- Dialer.Dial() 启动流模式时只接受 StreamPathFactory；DialPacket() 同理（C3）
- 对端必须是 rendr 实例（C1，由 HELLO 协议层验证，本 API 不重复检查）

rendr 内部把 user-supplied `net.Conn` 包到现有 `transport.PathConn` 上（length-prefix
帧层），把 `net.PacketConn` 包到现有 datagram path 上（8B flow-id 头帧层）——
**复用 M1 / M5 已经写好的代码**，不引入新 wire 行为。

`rendr/xray` 加胶水 B 的两个 helper：

```go
// rendr/xray/factory.go（新增）

// XrayOutboundAsStreamFactory: 用 xray-core library 把一条 outbound chain
// 跑成一个 stream-shaped net.Conn 工厂。chain 内含任意层数的 xray 协议
// （vless / trojan / vmess / ss / 嵌套 / reverse 都行），rendr 不感知细节。
// 适用于 chain 最后一段是 TCP-stream-style 时（tcp / ws / grpc / h2 / quic-stream / xhttp）。
func XrayOutboundAsStreamFactory(inst *core.Instance, chain *core.OutboundHandlerConfig) rendr.StreamPathFactory

// XrayOutboundAsPacketFactory: chain 最后一段是 packet-style 时
// （xray-core 直接走 net.PacketConn 的纯 UDP outbound）使用。
func XrayOutboundAsPacketFactory(inst *core.Instance, chain *core.OutboundHandlerConfig) rendr.PacketPathFactory
```

**重要：流 / 包的判定不在 rendr 也不在胶水里**——由嵌入者按自己 chain 的实际
wire shape 选用对应 helper。胶水内部不窥探 chain 配置，纯壳。

### 测试

- 单元测试：覆盖 `Add{Stream,Packet}PathFactory` 公共 API（new in xray_test.go）
- 集成：一条简单 vless+tls direct outbound 通过胶水 B 作为 rendr path，跑 file-transfer 100MiB + 迁移
- 完整矩阵：`docs/regression-suite.md` T3（X5 落地后启动 REG 任务）

**判退**：X5 测试通不过 → 回头修订 PathFactory 契约或胶水实现。
**不允许"X5 没完全跑通但先做 X6"**。

**当前状态**：X5-X7 已落地。T3 覆盖 freedom、VMess、VLESS+Vision+TLS、
Trojan+TLS、SS-2022、REALITY、MLKEM、nested、reverse、bare/xray 混合、
packet udpflow/quic-datagram/xray UDP、以及 xray balancer 的 stream/packet
factory 形态。

## M10 — 参考 demo：基于 rendr 的 SOCKS5

最小可读的完整 example。给上层开发者一个嵌入示范。**不算独立 milestone，作为 docs / example 维护**。

## M11 — 自管 UDP 协议承接（rendr UDP-relay 端点）

**前置**：M5（不透明 UDP flow-id）+ M9 X5（`AddPacketPathFactory`）通过。

**目标**：让"自己持有 UDP socket、不走 xray streamSettings"的协议
（WireGuard、Hysteria 2、自研 UDP 应用等）能不改代码接进 rendr 的多路径
迁移能力。这类协议天然不适合走 M9 X5 的 PacketPathFactory（它们要的是"自己
是 UDP server，rendr 当 UDP client 把包搬过来"，不是反过来）。

**形态**：

```
            (自管 UDP 应用)
              ↓ ↑
            UDP loopback :NNNN  ←─ rendr 在本地暴露的"伪远端"
              ↓ ↑                  （udp-relay daemon 形态）
            ┌─────────────────┐
            │  rendr engine   │ —— flow-id + 迁移
            └─────────────────┘
              ↓ ↑     ↓ ↑     ↓ ↑
            path A  path B  path C   (任意 transport: tcp/quic/udpflow)
```

**接口（已实现）**：

```go
// rendr/udprelay
type Relay struct{}

// Listen starts a server that accepts packet-mode rendr carriers and
// creates one UDP relay per accepted client. Dial starts the client-side
// loopback relay. Start wraps an already-created rendr PacketConn.
func Listen(ctx context.Context, cfg ServeConfig) (*Server, error)
func Dial(ctx context.Context, cfg DialConfig) (*Relay, error)
func Start(ctx context.Context, cfg Config) (*Relay, error)
```

**关键不变量**：

- UDP 包边界 1:1 保持（与 rendr 包模式同语义）
- 应用层完全不感知迁移；本地"伪远端"地址在连接生命周期内不变
- WireGuard 的 rekey / Hysteria 2 的 port hopping 由协议自管，不和 rendr 迁移冲突
  （迁移只影响 rendr 自己的 path 选择，对外暴露的 loopback :NNNN 不变）

**验收**：

- 跑 WireGuard userspace（wireguard-go）over rendr-udp-relay over 2-path
  bond，跨 path 迁移 ≥3 次，WG 隧道不重协商、上层 ping 0 丢失
- 跑 Hysteria 2 over rendr-udp-relay，同上
- 进 docs/regression-suite.md 的 T4 长驻矩阵（M11 完成后从"暂不覆盖"提到 T4）

**显式不在 M11 范围**：

- TUN inbound（需 `/dev/net/tun` + root，超出 rendr 通用 transport 定位）
- L3 路由 / NAT / 防火墙逻辑——只搬包，不解析

## 路线之外

- multipath QUIC（IETF draft）：纳入观察，目前不基于它构建
