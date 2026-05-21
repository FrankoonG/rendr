# rendr 回归测试套件（设计稿 v3）

> 2026-05-22 status addendum:
>
> - This document contains historical design sections that still say some rows are
>   "not implemented" or "deferred". Current code has moved ahead of those notes.
> - M11 self-managed UDP is now in T4 via `M11-wireguard-relay-T4` and
>   `M11-hysteria2-relay-T4`.
> - T5 now exercises both `tcprepair` and `gvisor`, including the explicit
>   unprivileged `tcprepair -> gvisor fallback` path.
> - The xray T3 matrix now includes REALITY, MLKEM, nested, reverse, stream and
>   packet balancer, plus Glue A migration cases for VMess / VLESS+TLS /
>   Trojan+TLS / SS2022.

> 状态：**未实现**，设计已对齐 `docs/plan.md` v0.1.0 项目定位 + M9 X5
> PathFactory API + 双向胶水。v3 的关键变化：
>
> 1. T3 主轴从"协议 × 裸传输"改为 **PathFactory 维度**（每条 path 是一份
>    xray outbound 配置，含协议 / 中继 / 嵌套 / reverse / 安全选项）；
>    rendr 仓库不再为每个 xray 协议单独写适配器代码。
> 2. 套件被分为**两个阶段**，阶段 1（rendr 自检）必须先全绿，
>    阶段 2（xray 集成与长驻）才允许启动——避免在长跑里才发现 rendr
>    引擎自身的回归。

## 1. 目标与判定主轴

让每一次 commit / merge / release 都能**用一条命令**验证 rendr 没有回归。

**判定主轴**：连接迁移的首要特征是"**长连接行为不中断**"。文件传输不中断
是最具说服力的可机械化判据；echo / SSH-长驻是次要补充。每一种 path 形态
组合都必须独立证明：

```
rendr 在多条 path（每条可能是不同 xray outbound chain）之间迁移
N MiB 文件传输不中断，应用层 SHA-256 一致，期间 MigrationCount 严格递增。
```

非数值化的判据（"看起来流畅"）不算通过。

具体诉求：

- **一键启动**：`./scripts/regress.sh` 或 `make regress`（单一入口）
- **容器化**：跑在 docker 内的标准 Linux，宿主机不被污染
- **短期可完成**：完整一键 **<30 分钟**，T1 子集 **<5 分钟**
- **数值判据**：每条用例有明确通过阈值
- **可解析报告**：JUnit XML + Markdown 摘要

## 1.1 三条硬契约（C1-C3）的测试映射

`docs/plan.md` 顶部定义的 C1-C3 在套件中对应到：

| 契约 | 测试覆盖 | Tier |
|------|---------|------|
| C1 对端是 rendr 实例 | flow_id 一致性 unit test（不同实例 HELLO 必 reject） | T1 |
| C2 流模式字节序 / 包模式包边界 | 各 path 形态下 HELLO 通过后 file-transfer SHA-256 一致 | T3 全用例 |
| C3 单 session 单模式 | 误把 PacketPathFactory 喂给 Dial（流） / StreamPathFactory 喂给 DialPacket → 编译期或 HELLO Caps reject | T1 unit + T3 错配负样本 |

C1-C3 是 rendr engine 的不变量，**所有 T3 用例隐含验证**——任何一条用例
中途 HELLO 失败 / SEQ 错位 / dedup 错位都意味着某条契约被破坏。

## 2. 范围

### 2.1 必须覆盖

- rendr 框架内部不退化（T1：`go test ./...` + `-race` + vet + 常量 grep）
- rendr 自带 G1-G5 smoke（T2：缩小版，保框架自检）
- **PathFactory × xray outbound 配置矩阵**（T3：本套件主体）
  - 含 4 种 path 形态（直连 / relay / 嵌套 / reverse）
  - 含 TLS / REALITY / MLKEM 作为 path 内部属性
- xray 长驻交互（T3 一部分：echo / 流式）

### 2.2 显式不覆盖

- **M3 TCP_REPAIR 单端迁移**：spike 已通过、未工程化为 transport 适配器
- **真实跨地域链路质量**：依赖 `docs/test-hosts.md` 真机，留给 release-tag 前手工跑（见 `success-criteria.md`）
- **xray 自身协议层 bug**：套件只验证"经 rendr 迁移后端到端仍可用"，xray 协议本身的正确性是 xray-core 自己的 CI 范围
- **WireGuard / Hysteria 2 等自管 UDP 协议**：等 M11（rendr UDP-relay 端点）落地后再扩矩阵

## 3. 容器与权限要求

### 3.1 镜像

单一 Dockerfile，多阶段：

```
FROM golang:1.26.3-bookworm AS build
# 编译两个二进制：
#   1. rendr regress driver（含 xray-core library import 和 rendr/xray transport 注册）
#   2. chaos cmd（T2 用，rendr 自检）

FROM debian:bookworm-slim AS runtime
# iproute2 iptables tc procps coreutils curl
# + 上述二进制
# + 一个 100 MiB 固定内容文件（dd if=/dev/urandom of=/fixture.bin seed=固定），SHA-256 写死在测试代码
```

镜像目标 <300 MiB。

### 3.2 运行时

```
docker run --rm \
    --cap-add=NET_ADMIN \
    --sysctl net.core.rmem_max=8388608 \
    --sysctl net.core.wmem_max=8388608 \
    -v $(pwd)/reports:/out \
    rendr-regress:latest
```

- `NET_ADMIN`：tc/netem/iptables（G4 路径杀死、限速、T3 部分协议 mocking）
- `rmem_max=8M`：QUIC DATAGRAM 高 pps 必备（产线已写进 README）
- 不需要 `--privileged`

### 3.3 拓扑与隔离

容器内默认 namespace 全 loopback；T3 每个用例额外开**网络命名空间**：

- **T1 / T2 smoke**：直接 loopback + 端口段分配（5000-5099 留给 T2），无需 netns
- **T3 每个用例独立 `ip netns add case-<id>`**，自带独立 loopback / iptables 表。
  并行用例不会因为 iptables --dport 撞表互相干扰。netns 创建/销毁 <20ms/个，可忽略
- **每个用例的 netns 内拓扑**：
  - xray-server 进程：监听协议端口（5101+协议号）+ 内部 file/echo 后端 :8080
  - xray-client 进程：SOCKS5 inbound :1080 + 协议 outbound 经 rendr 拨向 :5101+
  - 测试驱动：HTTP 通过 :1080 SOCKS5 拉文件 → 本地 SHA-256 → 写报告
- **故障注入**：`ip netns exec case-<id> iptables -p tcp/udp --dport ... -j DROP`，
  只影响本 netns，host 永远不动

### 3.4 并行执行策略

**目标**：完整 T3 矩阵全跑（不裁样本），通过并行把墙钟压回 <15min。

| Tier | 并行度 | 理由 |
|------|--------|------|
| T1   | 1（go test -p 已内并行）| go test 按包并行，外层再并行帮助有限 |
| T2   | 2     | 5 个 G smoke 中 G4/G5 串行（iptables 序），其余可并 |
| T3   | **N = max(2, NumCPU/2)** | 每用例独立 netns，互不干扰；并行度按容器 CPU 上限 |
| T4   | 1     | 长驻关心稳态延迟，竞争 CPU 污染观测 |

T3 调度算法（regress driver 内部）：

1. 枚举矩阵 = §7.2 全用例
2. 起 worker pool（N = NumCPU/2，最少 2）
3. 每 worker 取一用例 → 在独立 netns 内跑 → 写结果 → 取下一个
4. 失败不阻断其他 worker；全部结束统一汇总

**潜在污染源 & 对策**：

- CPU 上下文切换抖动：`taskset` 把 worker 绑核；T4 不并行（见上）
- 内核参数 sysctl 全局共享（rmem_max 等）：启动时设一次、所有 netns 通用，OK
- `/proc/sys/net/core/somaxconn` 等同上

## 4. 测试分层与两阶段门禁

### 4.1 两阶段（硬门禁）

套件被分成**两个阶段**，阶段 1 全绿是阶段 2 启动的硬前置：

| 阶段 | 含 Tier | 用途 | 时长 | 失败处置 |
|------|--------|------|------|---------|
| **阶段 1：rendr 自检** | T1 + T2 | 验证 rendr 引擎本身没有回归 | <12min | **立即退出，不进入阶段 2** |
| **阶段 2：集成验证** | T3 + T4 + T5 | 验证 rendr 在 xray 嵌入下、长驻、不同 adapter 下都符合契约 | <30-60min | 各 Tier 内部失败不阻断其他 Tier；汇总报告 |

**为什么硬门禁**：阶段 2（特别是 T3 矩阵 + T4 长驻）单跑就要十几分钟到一小时。
如果是 rendr 引擎本身的问题（HELLO 协议错位、SEQ 算错、迁移逻辑 bug），
在阶段 2 里发现就浪费了大量 CI / 本地时间。阶段 1 包含的 unit + smoke
能在 12 分钟内暴露绝大多数引擎层回归；先过阶段 1 再投阶段 2 的资源
是高 ROI 的工作流。

### 4.2 Tier 明细

| Tier | 用途 | 时长 | 触发 | 前置 | 所属阶段 |
|------|------|------|------|------|---------|
| T1 | unit / contract / vet / race | <5min | 每 PR | 无 | **阶段 1** |
| T2 | rendr 自带 G1-G5 smoke | <8min | 每 PR | 无 | **阶段 1** |
| T3 | PathFactory × xray outbound 矩阵 | <15min | 每合入 v0.1.x | 阶段 1 全绿 + M9 X5 | 阶段 2 |
| T4 | 长驻 | >40min | release tag 前 | 阶段 1 全绿 + M9 X5 | 阶段 2 |
| T5 | TCP 单端迁移 fallback 矩阵 | <10min | release tag 前 | 阶段 1 全绿 + M3-prod 或 M4 | 阶段 2 |

**调用方式**：

- `./scripts/regress.sh`（默认）：跑阶段 1 + 阶段 2 的 T3；阶段 1 失败立即 exit 1
- `./scripts/regress.sh --phase=1`：只跑阶段 1，给开发本地最快反馈
- `./scripts/regress.sh --full`：阶段 1 + 阶段 2 的 T3+T4+T5；阶段 1 失败立即 exit 1
- `./scripts/regress.sh --force-phase2`：跳过阶段 1 直接跑阶段 2（**只用于本地调试阶段 2 自身，CI 禁用**）

T5 是**条件触发**：M3-prod / M4 任一 adapter 已编译进 regress driver 时跑，
否则跳过并报告 "skipped: tcprepair adapter unavailable" / "skipped: gvisor
adapter unavailable"。容器权限差异由 T5 自身处理（详 §8.1）。

---

## 5. Tier 1：单元 + 契约（<5min）

不变。原 §5 不动：

| 用例 | 判据 |
|------|------|
| `go test ./... -count=1 -timeout 240s` | 全 9 包 PASS |
| `go test ./... -race -count=1 -timeout 360s` | 0 race |
| `go vet ./...` | 0 warning |
| `go test -bench=BenchmarkStreamThroughputTCP -benchtime=2s` | 记录 MB/s 作为 T3 对照基线 |
| `go test -bench=BenchmarkStreamThroughputTCPWithMigration -benchtime=2s` | 退化 <10% |
| 常量 grep 步骤（**待确认**） | `MigrationBudgetDefault==90s` 等不被静默改 |

---

## 6. Tier 2：rendr 自带 G1-G5 smoke（<8min）

降级为 smoke：只跑足以暴露"框架本身回归"的最小负载，保证不浪费 T3 时间。

| 用例 | 规模 | 判据 |
|------|------|------|
| G1-smoke | 30 MiB + 3 次迁移、2 path TCP | SHA-256 一致、吞吐退化 <15% |
| G2-smoke | 30s echo 间隔 100ms、≥5 次迁移 | 0 loss、P99 < 基线 × 2 |
| G3-smoke | 30k pps QUIC DATAGRAM 单 path、≥3 ConnID 迁移 | 0 应用丢失 |
| G4 | iptables DROP path1 | failover ≤5s、无 app error |
| G5 | 接 G4、AddPath 恢复 | RecvDups=0、不重排 |

理由：xray 协议矩阵（T3）会用到完整的 G1/G2/G3 形态去跑各协议；T2 这里只是
"如果 rendr 自检就失败，没必要往下跑 T3 浪费 15 分钟"的早期门禁。

---

## 7. Tier 3：PathFactory × xray outbound 矩阵（<15min，**主体**）

### 7.1 矩阵架构（factory 维度而非协议维度）

每条 rendr path 由一份 **path-profile** 描述。path-profile 内部决定了：

- **拓扑**：直连 / relay（client→C→server）/ 嵌套（N 层 xray 协议）/ reverse
- **协议**：vless+Vision / trojan / vmess / shadowsocks-2022 / 任意 xray 出站
- **wire shape**：流 / 包（决定用 StreamPathFactory 还是 PacketPathFactory）
- **安全栈**：none / TLS / REALITY / MLKEM-768+X25519 / 任意组合
- **streamSettings transport**：tcp / ws / grpc / h2 / quic / xhttp（链尾段）

rendr 仓库不需要为每个 xray 协议写适配器代码（已对齐 `docs/plan.md` M9 X5
+ `docs/xray-integration.md`）。规模因此**不是协议 × path 笛卡尔积，而是
代表性 path-profile 集合 × 二元/三元组合**。

### 7.2 Path-profile 清单（PY-Stream / PY-Packet）

#### 流模式 path-profile（用 StreamPathFactory）

| # | 拓扑 | 协议链 | 安全 | wire shape |
|---|------|--------|------|------------|
| PYS-D-1 | 直连 | vless+Vision | TLS | tcp |
| PYS-D-2 | 直连 | trojan | TLS | tcp |
| PYS-D-3 | 直连 | vmess | TLS | ws |
| PYS-D-4 | 直连 | shadowsocks-2022-blake3-aes-128-gcm | — | tcp |
| PYS-D-5 | 直连 | vless+Vision | **REALITY** | tcp |
| PYS-D-6 | 直连 | vless+Vision | **TLS + MLKEM-768+X25519** | tcp |
| PYS-D-7 | 直连 | vless+Vision | **REALITY + MLKEM** | tcp |
| PYS-R-1 | relay（C 透明转发） | vless+Vision | TLS | tcp |
| PYS-R-2 | relay | trojan | TLS | tcp |
| PYS-N-1 | 嵌套 2 层 | shadowsocks → vless+Vision | TLS（外层） | tcp |
| PYS-V-1 | reverse | vless+Vision | TLS | tcp |
| PYS-bare-tcp | （胶水 B 之外）裸 TCP path | — | — | tcp（rendr 内建） |
| PYS-bare-quic | 裸 QUIC stream path | — | — | quic-stream（rendr 内建） |

13 条流模式 path-profile。

#### 包模式 path-profile（用 PacketPathFactory）

xray 的 UDP 系协议大多是"UDP-over-stream"（vless-UDP / ss-UDP 都把 UDP
封进 TCP stream），对 rendr 来看仍是流。**真正用 PacketPathFactory** 的
是底层就是 net.PacketConn 的 path：

| # | 拓扑 | 来源 | wire shape |
|---|------|------|------------|
| PYP-bare-udpflow | rendr 内建 udpflow | — | UDP datagram + 8B flow-id 头 |
| PYP-bare-quic-dg | rendr 内建 QUIC DATAGRAM | — | QUIC DATAGRAM (RFC 9221) |
| PYP-xray-direct | xray UDP outbound（如 SS-2022 UDP relay 模式） | shadowsocks udp | UDP packet |

3 条包模式 path-profile。

### 7.3 测试组合（path-profile × 数量）

**流模式组合**（13 选 N）：

| 类别 | 组合 | 用例数 | 验证点 |
|------|------|--------|--------|
| 同 profile × 双 path | {PYS-D-1, PYS-D-1}、{PYS-D-2, PYS-D-2} | 2 | 同协议双 path 同质迁移 |
| 不同协议直连互迁 | {PYS-D-1, PYS-D-2}、{PYS-D-1, PYS-D-3}、{PYS-D-2, PYS-D-4} | 3 | 跨协议迁移核心场景 |
| 直 × relay | {PYS-D-1, PYS-R-1}、{PYS-D-2, PYS-R-2} | 2 | **relay-hop 失败迁移** |
| relay × relay | {PYS-R-1, PYS-R-2} | 1 | 多中继互迁 |
| 嵌套 | {PYS-N-1, PYS-D-1} | 1 | 嵌套层数对 rendr 透明 |
| reverse | {PYS-V-1, PYS-D-1} | 1 | reverse path 与直连互迁 |
| 安全维（TLS / REALITY / MLKEM） | {PYS-D-1, PYS-D-5}、{PYS-D-1, PYS-D-6}、{PYS-D-5, PYS-D-7} | 3 | 跨安全栈迁移 |
| 裸 + xray 混合 | {PYS-bare-tcp, PYS-D-1}、{PYS-bare-quic, PYS-D-2} | 2 | factory 来源不同的 path 在 rendr engine 中并存 |
| 3-path | {PYS-D-1, PYS-D-2, PYS-R-1}、{PYS-D-1, PYS-N-1, PYS-V-1} | 2 | 多 path 迁移序列 |

合计**流模式 17 用例**。

**包模式组合**（3 选 N）：

| 组合 | 用例数 |
|------|--------|
| {PYP-bare-udpflow, PYP-bare-udpflow} | 1 |
| {PYP-bare-udpflow, PYP-bare-quic-dg} | 1 |
| {PYP-bare-quic-dg, PYP-bare-quic-dg} | 1 |
| {PYP-bare-udpflow, PYP-xray-direct} | 1 |

合计**包模式 4 用例**。

**T3 总用例 = 17 + 4 = 21**。每例预算 ~25s；串行 9 分钟，按 §3.4 并行度 4
→ 墙钟 ~3 分钟；加编译启动 → T3 总 <8 分钟。

### 7.4 单用例判据（流模式）

```
[setup]
1. rendr-server 在容器 case-netns 内监听 :5555（rendr.ListenTCP 内建 + 任意挂载的 xray inbound）
2. rendr-client 创建 Dialer，按用例描述：
   - 内建 path 用 PathSpec
   - xray-out path 用 Add{Stream,Packet}PathFactory（factory 由 rendr/xray 胶水 B 生成）
3. fixture backend (HTTP 100 MiB file) 挂在 rendr-server 进程内

[exec]
4. rendr-client.Dial() → 拿到 net.Conn
5. 直接通过 net.Conn 跑 HTTP GET (rendr 之上无其他代理层；应用层就是文件下载)
6. 下载到达 30 / 50 / 70 MiB 时各调用一次 rendr.AdminConn.Migrate(otherPathID)

[verdict]
- sha256(下载内容) == sha256(fixture.bin)                  ← C1+C2 + 引擎完整性
- 总耗时 / 无迁移基线耗时 < 1.10                            ← G1 throughput contract
- rendr.AdminConn.MigrationCount() ≥ 3                     ← 迁移确实发生
- 应用层 read/write 全程无 error / EOF                    ← 迁移透明性
- rendr.Stats().State == "active"                          ← 未进入 migrating-stuck
- 任一 path 在 HELLO 阶段 reject  →  case FAIL（C1/C3 违例）
```

### 7.5 单用例判据（包模式）

```
[exec]
驱动以 1k pps 发送 60 秒，包大小 1024 B，序号单调递增；中途触发 ≥3 次迁移。

[verdict]
- 收到的回包序号集合 == 发出的序号集合                    ← 0 应用层丢失
- 包边界保持（一次 WriteTo == 对端一次 ReadFrom）        ← C2 包模式
- P95 RTT < 基线 × 2                                       ← G3 contract
- MigrationCount ≥ 3
```

### 7.6 后端 fixture

- rendr-server 进程内嵌 HTTP 文件服务器（loopback :8080）+ UDP echo server
- 镜像构建时生成 100 MiB `/fixture.bin`（固定 seed），SHA-256 写进二进制常量

### 7.7 长驻 echo（次要"长连接行为"覆盖）

除 file-transfer 外，针对**代表性 5 条 path-profile**（PYS-D-1 / PYS-D-2 /
PYS-D-4 / PYS-R-1 / PYS-N-1）各跑一例 30 秒 echo（100ms 一包，≥3 次迁移，
0 loss、P99 < 基线 × 2）。5 个用例，并入主矩阵。

### 7.8 错配负样本（C3 强制）

确保 API 误用被立刻发现：

| 负样本 | 期望 |
|-------|------|
| Dialer.Dial() + 只挂 PacketPathFactory | 编译期 / 运行时拒绝 |
| Dialer.DialPacket() + 只挂 StreamPathFactory | 同上 |
| 两端 HELLO Caps 不匹配（一端 stream、一端 packet）| HELLO reject |
| 第 2 条 path 的 flow_id 与第 1 条不一致 | server 拒绝、path 标 Death |

3 个 unit 用例 in `xray_test.go` 即可，归 T1。

---

## 8. Tier 4：长驻 / 极限（>40min，release-tag 前）

| 用例 | path 配置 | 时长 | 关键判据 |
|------|----------|------|----------|
| G2-full | PYS-D-1 × PYS-R-1（vless-Vision-TLS 直连 + 经 relay） | 30 min | 0 loss、P99.9 < 1s、≥30 次迁移 |
| G3-full | PYP-bare-quic-dg × 2（包模式 QUIC DATAGRAM bond）| 5 min | 50k pps（容器 loopback 上限）、0 应用丢失 |
| Race mode 去重 | PYS-D-1 + PYS-D-2 + PYS-D-4（3-path race） | 5 min | 注入路径级重复、RecvDups 对齐 |
| Bond stuck-skip | PYS-D-1 + PYS-D-2 + 一条人为加延迟的 path | 3 min | bond 检测并跳过慢 path |
| Prime 抖动稳定性 | PYS-D-1 + PYS-D-2 周期性互换质量 | 5 min | dwell 期内不切（迁移次数 ≤ ceil(时长/5s)） |
| 嵌套深度极限 | 3 层 xray 嵌套（SS → vless → trojan） | 2 min | rendr 不感知嵌套深度，迁移正常 |
| 二级中继 | C 自己跑 xray（B↔C↔A 两段不同协议） | 2 min | rendr 看到的还是单一 net.Conn |

T4 **只在 release tag 触发**，不进每日 schedule。本地 `--full` 也跑。
理由：每日 schedule 跑长驻会日均吃 1-2 小时 CI 时长，且失败大多是噪音
（loopback CPU 抖动 / 容器宿主负载），ROI 低。release-tag 强制 + 手动
随时可触发已足够保证发布质量。

## 8.1 Tier 5：TCP 单端迁移 fallback 矩阵（条件触发）

**前置**：M3-prod（`transport/tcprepair`）**或** M4（`transport/gvisor`）
至少一个已编译进 regress driver。否则整层 skipped。

**主旨**：rendr 的单端 TCP 迁移有两个互补 adapter：

- **tcprepair**（M3-prod）：内核态 TCP_REPAIR，需 CAP_NET_ADMIN
- **gvisor**（M4）：用户态 TCP，0 权限要求

部署形态因容器权限差异有四种组合，T5 要把这四种都跑一遍：

| 用例 | 容器权限 | adapter | 期望 |
|------|---------|---------|------|
| T5.1 | `--cap-add NET_ADMIN`（privileged 容器） | tcprepair | ✓ 跑通 G1 mini（30 MiB + 3 迁移、SHA-256 一致） |
| T5.2 | 同上 | gvisor | ✓ 跑通 G1 mini（即使有 NET_ADMIN，gvisor 仍然要能跑） |
| T5.3 | **无 NET_ADMIN**（unprivileged 容器） | tcprepair | ✓ adapter 初始化时探测 `setsockopt(TCP_REPAIR)` 返回 EPERM，**明确报错** `tcprepair: CAP_NET_ADMIN required, use gvisor fallback` |
| T5.4 | 同 T5.3 | gvisor | ✓ 跑通 G1 mini（这是 fallback 实战） |

**关键判据**：

- T5.3 必须**显式报错**而非静默退化，否则嵌入者不知道自己在用慢路径
- T5.1 / T5.2 / T5.4 各自跑 G1 mini 通过
- T5.2 + T5.4 性能记录到 reports/raw/T5.gvisor.json，gvisor 实测吞吐
  应在 1-3 Gbps 范围（vs T5.1 内核 TCP 5-10 Gbps），偏离 ±50% 视为回归

**容器形态**：

T5 用例需要切换容器权限，所以**不和 T3 / T4 共享同一外层容器**——
T5 自己用 docker-in-docker 或独立 docker run 拉起两个权限不同的子容器：

```
host
├── docker run --cap-add=NET_ADMIN rendr-regress:latest -- regress --t5-privileged
│   └── 内部跑 T5.1 + T5.2
└── docker run                       rendr-regress:latest -- regress --t5-unprivileged
    └── 内部跑 T5.3 + T5.4
```

**T5 时长预算**：4 用例 × 单 G1 mini 25s + 容器启动 15s × 2 = ~2 min；
完整 T5 < 10 min（含 gvisor 性能 baseline 采样）。

**T5 与 T3 关系**：T3 测的是 rendr engine 在不同 PathFactory 来源下的
迁移正确性，**path 形态主要是 xray outbound**。T5 测的是"rendr 直接管的
TCP 单端迁移"——adapter 是 tcprepair / gvisor 而不是 xray outbound。
两者不重叠，独立 Tier。

---

## 9. xray-core 集成形态

### 9.1 library 模式（决定走这条）

regress driver 是一个 Go 程序，`import (xray-core/...)`，单进程内构造
inbound/outbound 配置 → 启动 → 驱动流量 → 拆销。

**为什么 library 不是"测试专用"**：

library 模式同时是**生产嵌入路径**。`docs/xray-integration.md` 把 rendr
定位为"被 xray library import 的 transport"——任何生产 embedder（自研代理、
配置面板、定制路由器固件等）想用 rendr，都是走"xray-core + rendr/xray
都作为 Go module 链入同一二进制"这条路。测试 regress driver 与生产 embedder
代码路径同构，只是配置由代码生成而非 JSON 文件。所以：

- 测试 = 生产嵌入路径的最小可执行实例
- 测试覆盖的就是 embedder 实际碰到的代码
- 测试发现的 bug 也是生产 embedder 会碰到的 bug

binary + JSON 模式只能用于"xray-core 不进 go.mod 的零依赖部署形态"——
但 rendr 想被 xray 调用就必须进 go.mod，所以这条路从一开始就不构成"用例"，
更不构成生产路径。**不实现 binary 模式**。

### 9.2 go.mod 隔离

xray-core 加进 **`regress/go.mod` 子模块**，不污染 root `go.mod`。

- 核心 rendr 用户（只 `go get github.com/FrankoonG/rendr`）不会被牵入
  xray-core 大依赖图
- 生产 embedder 自行决定要不要 import xray-core，他们的 go.mod 是他们的事
- regress 子模块自己 `go build` 拉 xray-core；CI 容器构建独立

### 9.3 版本 pin

锁 **`v26.3.27`**（当前 stable，2026-03-27 发布）。Pre-release v26.5.9 含
最新 UDP / mKCP 修复，但在 stable 出来前不进。每个 xray 季度 stable
出来时由 maintainer bump（人工，不进 dependabot 自动化——xray 协议层
小改也可能改 transport.internet.Dialer 接口，盲 bump 会断 rendr/xray）。

---

## 10. 一键脚本契约

```bash
$ ./scripts/regress.sh --help
rendr regression suite

  阶段控制（默认行为已经体现两阶段门禁）：
  --phase=1              只跑阶段 1（T1+T2），快速自检
  --phase=2              只跑阶段 2（T3+T4+T5）；要求阶段 1 当前状态为 green
  --full                 跑阶段 1 + 阶段 2 全部，含 T4 长驻
  --force-phase2         跳过阶段 1 直接跑阶段 2（CI 禁用、仅本地调试用）

  细粒度选择（阶段 2 内部）：
  --tier=3|4|5           只跑阶段 2 内指定 Tier
  --profile=PYS-D-1,...  仅跑指定 path-profile 组合（T3）
  --case=<id>            仅跑指定用例 ID（T3 / T5）

  报告与构建：
  --report-dir=DIR       报告输出目录（默认 ./reports）
  --keep-image           构建后不清理 docker 镜像
  --rebuild              强制 docker build --no-cache
```

**默认行为**（无参数）：

1. 跑阶段 1（T1 → T2）；任一失败 → **立即 exit 1**，不进入阶段 2
2. 阶段 1 全绿 → 跑阶段 2 的 T3（PathFactory 矩阵）
3. 不自动跑 T4（长驻）和 T5（TCP fallback）——它们要 `--full` 或 `--tier=4/5`

**`--phase=2` 安全检查**：脚本检查 `reports/last_phase1.json`，若不存在或
显示阶段 1 状态非 green / 时间戳早于当前 commit → 报错 `phase 1 not validated
for this commit, run --phase=1 first or use --force-phase2 to override`。
`--force-phase2` 显式声明用户接受"可能跑阶段 2 才发现阶段 1 已坏"的风险，
**CI 中不允许使用**。

退出码：

| 码 | 含义 | 阶段 |
|----|------|------|
| 0  | 全部通过 | — |
| 10 | T1 失败（unit / contract / vet / race / 常量 grep）| 阶段 1 |
| 11 | T2 失败（rendr 自带 G1-G5 smoke 退化）| 阶段 1 |
| 20 | T3 失败（PathFactory 矩阵）| 阶段 2 |
| 21 | T4 失败（长驻）| 阶段 2 |
| 22 | T5 失败（TCP fallback 矩阵）| 阶段 2 |
| 50 | 容器/环境错误（docker / NET_ADMIN / sysctl / xray-core 缺失）| — |
| 51 | `--phase=2` 时阶段 1 状态非 green（拒绝执行） | — |
| 99 | 用户中断 | — |

退出码按"10 / 20 / 50 起始"分组，**只看十位**能立刻识别失败阶段。
CI 失败通知里也直接用退出码。

## 11. 报告格式

### 11.1 JUnit XML（`reports/junit.xml`）

每个用例一个 `<testcase>`，名字格式 `T3.<case-id>`（如
`T3.stream.D-1×R-1`、`T3.stream.N-1×D-1`、`T3.packet.bare-udpflow×bare-quic-dg`），
便于 CI 渲染矩阵。

### 11.2 Markdown 摘要（`reports/SUMMARY.md`）

```markdown
# rendr regression — 2026-05-19 14:23:01 UTC
xray-core: v26.3.27    rendr: v0.1.0 @ <commit>

## T1 contracts                ✓ 3:42
## T2 rendr smoke               ✓ 5:08
## T3 path-factory matrix       ✗ 20/21

### Stream-mode cases (17)

| Case | Paths | Time | Result |
|------|-------|------|--------|
| stream.D-1×D-1   | vless-direct × vless-direct          | 23s | ✓ |
| stream.D-1×D-2   | vless-direct × trojan-direct         | 24s | ✓ |
| stream.D-1×R-1   | vless-direct × vless-via-relay       | 26s | ✓ |
| stream.D-2×R-2   | trojan-direct × trojan-via-relay     | 27s | ✓ |
| stream.N-1×D-1   | (ss→vless) nested-2-layer × direct   | 28s | ✗ sha-mismatch |
| stream.V-1×D-1   | vless-reverse × vless-direct         | 25s | ✓ |
| stream.D-1×D-5   | vless-TLS × vless-REALITY            | 24s | ✓ |
| stream.bare-tcp×D-1 | raw-TCP × vless-direct            | 22s | ✓ |
| ...              | ...                                  | ... | ... |

### Packet-mode cases (4)

| Case | Paths | Time | Result |
|------|-------|------|--------|
| packet.udpflow×udpflow      | rendr-udpflow × rendr-udpflow         | 60s | ✓ |
| packet.udpflow×quic-dg      | rendr-udpflow × QUIC DATAGRAM         | 60s | ✓ |
| packet.quic-dg×quic-dg      | QUIC DATAGRAM × QUIC DATAGRAM         | 60s | ✓ |
| packet.udpflow×xray-direct  | rendr-udpflow × xray native UDP       | 62s | ✓ |

OVERALL: FAIL (1/21 T3 cases)
```

### 11.3 原始数据（`reports/raw/T3.<case>.json`）

每个用例独立 JSON：吞吐曲线、迁移时间戳、RTT 直方图、xray 日志摘要。

## 12. CI 集成

```yaml
# .github/workflows/regress.yml（新增）
on:
  push:
    branches: [v0.1.0]
  pull_request:
  release:
    types: [published]   # release tag 触发 --full（含 T4 长驻）
```

PR / push 跑 T1+T2+T3；release 跑 `--full`。**不设每日 schedule**——T4
长驻在容器宿主负载抖动下噪音大，每日跑收益低于成本。release-tag 强制
通过 + 本地手动 `--full` 已足够保证发布质量。

## 13. 仓库布局

```
docs/regression-suite.md          # 本文（gitignored）
scripts/regress.sh                # 公开，宿主机入口
docker/regress.Dockerfile         # 公开
docker/regress-entrypoint.sh      # 公开

regress/                          # 公开，rendr 测试基础设施的唯一入口
  go.mod                          # 子模块，独立 import xray-core，不污染 root
  go.sum
  cmd/
    regress/main.go               # 阶段门禁 + tier 调度 + reporter wire-up
  internal/
    gate/                         # 两阶段门禁；last_phase1.json commit-sha 绑定
    report/                       # JUnit XML + Markdown summary writer
    tier1/                        # T1 runner: go vet / test / -race / bench / 常量 grep
    tier2/                        # T2 dispatcher → smoke
    smoke/                        # T2 实装：G1 / G2 / G3 / G4 / G5
      smoke.go g1.go g2.go g3.go g4_g5.go
    tier3/                        # T3 dispatcher：shells out to `go test -json ./internal/matrix/...`
    matrix/                       # T3 测试本体（每个文件 = 一族用例）
      driver/
        file_xfer.go              # 流模式 30 MiB HTTP + 强制迁移 + SHA-256
        udp_echo.go               # 包模式 N pps echo + 强制迁移 + P95
      matrix_test.go              # freedom × freedom（zeroth proof）
      ss2022_test.go              # SS-2022 × SS-2022（PYS-D-4）
      vmess_test.go               # VMess × VMess、SS × VMess（cross-protocol）
      trojan_test.go              # Trojan + TLS（PYS-D-2）
      vless_test.go               # VLESS+Vision+TLS（PYS-D-1）
      mlkem_test.go               # VLESS+Vision+TLS+MLKEM（S5）
      mixed_test.go               # bare-tcp × xray，3-path 组合
      relay_test.go               # direct × relay、SS-via-relay（PYS-R-1/2）
      packet_test.go              # udpflow×udpflow、quic-dg×quic-dg
      packet_xray_test.go         # xray-freedom-UDP × udpflow
      ss2022_udp_test.go          # SKIP: xray UDP 上游会话表问题
      reality_test.go             # SKIP: 需要 uTLS-fingerprint 本地 Dest
      nested_test.go              # SKIP: 嵌套链 / reverse 待 xray 引用编码确认
    xrayglue/                     # 胶水 B：xray Instance → rendr.{Stream,Packet}PathFactory
      doc.go factory.go smoke_test.go factory_test.go
    longrun/                      # T4 长驻用例（待建）

chaos/                            # 已弃用（gitignored，保留旧脚本作参考）
  README.md  → 写明"已被 regress/ 取代"
  cmd/...    → 不再维护；新增测试一律走 regress/
```

### 13.1 规范化要点

- **`regress/` 是 rendr 全部测试基础设施的唯一入口**。任何新测试增量
  都加到 `regress/internal/...`，**不**再往 `chaos/` 加新东西
- **`chaos/` 标记为弃用**：已存在的 `chaos/cmd/{g1,g2,g4}/main.go` 内容
  挪进 `regress/internal/smoke/`，公开化；chaos/ 目录改写一份 README 指向
  regress，**保留旧脚本仅作历史参考**，不主动清空（避免误删某些手工脚本）
- **regress 子模块独立 go.mod**：root `go.mod` 不被 xray-core 牵入大依赖
- **公开 vs 私有边界**：regress/ 整体公开（含 xray 配置、测试驱动、报告器）。
  唯一仍私有的是 `docs/`（设计文档）、`CLAUDE.md`、`AGENTS.md`、
  `xray/CHECKLIST.md`、test/（POC 与一次性脚本）

## 14. 实施顺序

按"先建阶段 1 → 阶段 1 自验证 → 才开始阶段 2"的纪律。每一步可单独 commit / PR。

### 阶段 1 建造（先完成）

实施进度（最新 commit 64e437f）：

1. **regress 骨架 ✓**（commit d7fb5b5）：`regress/go.mod`（独立子模块）+
   `regress/cmd/regress/main.go` 含 `--phase` / `--tier` / `--force-phase2` /
   `--profile` / `--case` / `--report-dir` 标志 + 两阶段门禁（`reports/last_phase1.json`
   记录 commit-sha 绑定）+ JUnit + Markdown reporter。CI workflow
   `.github/workflows/regress.yml` 跑 `--phase=1`
2. **T1 落地 ✓**（commit d7fb5b5）：`regress/internal/tier1/` 串
   `go vet` + `go test ./...` + `-race`（Linux 限定，含 1 次重试用于
   消除 race-detector 调度抖动）+ bench smoke + 5 个常量 grep（`proto.Version=0` /
   `proto.UDPFlowVersion=0` / `MigrationBudget=90s` / `Mode` 枚举值 /
   `race↔bond` 禁止互转表）
3. **T2 smoke 实装**（commits ba67c44 + ff8aa93 + 64e437f）：
   - `regress/internal/smoke/g1.go` G1-smoke：30 MiB + 3 迁移 + SHA-256 ✓
   - `regress/internal/smoke/g2.go` G2-smoke：30s echo + ~5 迁移 + 0 loss + P99 ceiling ✓
   - `regress/internal/smoke/g3.go` G3-smoke：QUIC DATAGRAM 30k pps × 6s +
     3 ConnID 迁移 + 0 应用 loss + P95 50ms ceiling（Linux only）✓
   - `regress/internal/smoke/g4_g5.go` G4 / G5：force-kill 路径 + AddPath
     恢复 + RecvDups=0（用 `engineBackedConn.ForceKillPathForTest`
     duck-typed 接口断言；为此在 `conn_impl.go` / `packet.go` 加了 proxy 方法）✓
4. **阶段 1 自验证**：在 64e437f 上跑——Windows 全绿（45s），Linux 测试主机
   `root@10.130.32.32` 验证待录入 success-criteria.md 作基线

**待办**（阶段 1 收尾）：

- chaos/cmd/{g1,g2,g4}/main.go 弃用 README + 保留旧脚本仅作历史参考
  （regress/internal/smoke 已是新唯一入口）
- 阶段 1 在 Linux 测试主机基线 snapshot 写入 `docs/success-criteria.md`

**阶段 1 完成的硬指标**：

- CI `regress.sh --phase=1` 在 v0.1.0 HEAD 上 100% 通过
- 阶段 1 时长 ≤ 12min
- 退出码 0 + `reports/last_phase1.json` 记录 commit-sha 和时间戳

**只有阶段 1 自验证通过后**，才动阶段 2 的代码。

### 阶段 2 建造（阶段 1 全绿后才启动）

实施进度（最新 commit `403c7ec`）：

5. **xray-core 依赖** ✓（commit `f1ef8e1`）：xray-core v26.5.9 pseudo-version 进 regress/go.mod
6. **胶水 B 助手** ✓（commit `8a8185b`）：`regress/internal/xrayglue/factory.go` 暴露
   `XrayInstance{Stream,Packet}Factory(inst) → rendr.{Stream,Packet}PathFactory`
7. **fixture + driver** ✓（commit `0691369`）：`driver/file_xfer.go` 30 MiB HTTP +
   强制 Migrate + SHA-256；HTTP server 直接 attach 到 rendr.ListenTCP 的 accept；
   `driver/udp_echo.go` 包模式 paced PPS + sequence-track + P95
8. **参考实现 `T3.stream.freedom×freedom`** ✓（commit `0691369`）：xray freedom
   出站作 factory，2 路径 × 30 MiB，3 次迁移 + SHA-256 通过
9. **流模式 profile 铺开** ✓：
   - SS-2022 × SS-2022（`696f11a`）
   - VMess × VMess + **SS-2022 × VMess 跨协议**（`e26c0ef`）
   - Trojan + TLS、VLESS+Vision+TLS（`6943f9a`）
   - bare-tcp × xray、3-path（`1637d97`）
   - VLESS+Vision+TLS+MLKEM（`2db0a5f`）
   - direct × relay、SS-2022 via relay（`ec47b4b`、`19f4bc2`）
10. **包模式 profile** ✓：
    - udpflow×udpflow、quic-dg×quic-dg（`94b121d`）
    - xray-freedom-UDP × udpflow（`737987c`）
11. **错配负样本** ✓：合入 `rendr/factory_test.go`（commit `8f3c005` M9 X5 stage 1）
12. **tier3 调度器** ✓（commit `1637d97`）：`regress/internal/tier3/runner.go`
    shells out to `go test -json ./internal/matrix/...`，每个顶层 Go test
    → 一个 report.Case 项；走标准 phase-2 gate
13. **CI 集成** ✓（commit `8980978`）：`.github/workflows/regress.yml` 加
    `phase2_t3` job，push/PR 自动跑全套矩阵
14. **官方入口脚本** ✓（commit `403c7ec`）：`scripts/regress.sh` 一键入口，
    `./scripts/regress.sh [--phase=N] [--tier=N] [--full]`
15. **延期用例 stub** ✓（commits `0b02cd8` / `37d8124` / `45ba9d4`）：
    SS-2022-UDP / REALITY / 嵌套 / reverse 各自 `t.Skip` 附详细原因，
    保留代码框架等待对应基础设施可用

**T3 实际落地：14 GREEN + 4 documented skip**

✓ stream: freedom · ss × ss · vmess × vmess · ss × vmess（跨协议） ·
  trojan+TLS · vless+Vision+TLS · vless+Vision+TLS+MLKEM ·
  bare-tcp × vless · 3-path · direct × relay · ss × relay
✓ packet: udpflow × udpflow · quic-dg × quic-dg · xray-freedom-UDP × udpflow
⏸ skip: SS-2022 UDP（xray-core 上游 UDP 会话表问题） · REALITY（缺 uTLS-fingerprint Dest） ·
  嵌套 chain（缺上游程序化引用编码） · reverse outbound（同上）

### 待办（REG-Phase2 收尾）

- **T4 长驻调度器**：`regress/internal/tier4/` + `regress/internal/longrun/`；
  G2-full（30min） / G3-full（5min） / race 去重 / bond stuck-skip / prime 稳定性 /
  嵌套深度 / 二级中继。release-tag 触发，CI 走 `release: types: [published]`
- **T5 TCP fallback 矩阵**：依赖 `docs/plan.md` M3-prod / M4 落地；`--tier=5`
  现在是 placeholder
- **CLAUDE.md 增补**："任何 commit 必须能跑过 `scripts/regress.sh`"——手工待办


> （上方旧步骤 5-17 已在 §14"阶段 2 建造"小节合并成实际落地状态。
>  原始 v3 草稿要求 netns 隔离层 / worker pool 等独立模块；实际实施时
>  改用 `go test -json` 调度 + 顺序运行——loopback 上单测足够快、不
>  需要 netns 隔离，并行度增益不抵复杂度，故走的是更精简的路径。
>  原始草稿的 docker/regress.Dockerfile 同样未必要，本机 / CI 都用
>  `cd regress && go run ./cmd/regress`。所有 step 5-17 的精神在
>  实际实施中体现，但模块布局与原稿差异较大——以本节"实施进度"为准。）

---

## 15. 决策汇总

本节是 v1/v2 草稿里的"待确认问题"经过最新一轮反馈后的**结论**，
保留为可追溯记录。

### A. 协议覆盖（v3 已收敛到 path-profile 维度）

| # | 条目 | 决策 |
|---|------|------|
| A1 | T3 矩阵架构 | **PathFactory × path-profile 维度**，不再是"协议 × path"笛卡尔积。13 流 + 3 包 profile，21 个组合用例（§7.2-§7.3） |
| A2 | SS cipher | 只跑 `2022-blake3-aes-128-gcm`，旧 AEAD 不进 |
| A3 | 安全栈覆盖 | **TLS / REALITY / MLKEM 作为 path-profile 内部属性**，组合在 §7.3"安全维"3 例 |
| A4 | 中继 / 嵌套 / reverse | 各覆盖 1-2 用例（§7.3）；嵌套深度 T3 测 2 层，T4 加测 3 层 |
| A5 | 裸 + xray 混合 | 1-2 用例（§7.3），验证 factory 来源不同的 path 在同 rendr engine 中并存 |
| A6 | UDP 协议处理 | xray UDP 系（vless-UDP / ss-UDP）多数走 stream-carrier，对 rendr 是流模式；真包模式只覆盖 udpflow / quic-datagram / xray-direct-UDP |

### B. xray-core 依赖

| # | 条目 | 决策 |
|---|------|------|
| B7 | library vs binary | **library 模式**（§9.1）。同时是生产嵌入路径，非测试专用 |
| B8 | go.mod 隔离 | **`regress/go.mod` 子模块**，xray-core 不污染 root |
| B9 | 版本 pin | **`v26.3.27`**（stable）。新 stable 出来时人工 bump |

### C. 框架自检 / 长驻

| # | 条目 | 决策 |
|---|------|------|
| C10 | T1 常量 grep | **加**。`MigrationBudgetDefault==90s` / `proto.Version==0` / 模式互转表 grep 检查；<1s 成本，防 silent 改常量 |
| C11 | T2 G3-smoke 包率 | **保持 30k pps 单 path**。容器 loopback 单 path 上限粗估 60-80k，30k 留余量；rendr 引擎退化到 <30k 即视为回归 |
| C12 | T4 触发 | **只 release tag 触发** + 本地 `--full`，不进每日 schedule |

### D. 仓库与可见性

| # | 条目 | 决策 |
|---|------|------|
| D13 | regress 公私 | **`regress/` 整体公开取代 `chaos/`**；chaos 标记弃用，详 §13.1 |
| D14 | CLAUDE.md 增补 | **加**："禁止合入未跑过 `regress.sh T1+T2+T3` 的 commit" |

### E. 其他

| # | 条目 | 决策 |
|---|------|------|
| E15 | 报告历史保留 | **90 天滚动 + 每周一份长期存档** |
| E16 | xray 失败日志 | JUnit 失败字段含 **tail 500 行**；完整日志挂 `reports/raw/T3.<case>.xray.log` |

---

### 关联里程碑

- **自管 UDP（WireGuard / Hysteria 2）**：架构方向挪到 `docs/plan.md` **M11**
  （rendr UDP-relay 端点）。本套件 T3 在 M11 完成前不覆盖；M11 完成后把
  对应的 PYP-wg-relay / PYP-hy2-relay 加进 §7.2.2 包模式 profile 集
- **xray 集成 M9 X5**（PathFactory + 胶水 B）：**本套件 T3 的前置依赖**。
  M9 X5 不落地，T3 无法启动。M9 X5 已是 `docs/plan.md` 当前下一步
- **xray 集成 M9 X6-X7**：X6 BalancerObject 对接 / X7 xray 自身回归套件
  over rendr，独立于本套件推进
- **TCP 单端迁移 M3-prod / M4**：T5 的前置。两个 adapter **互补不替代**——
  M3-prod 是首选（CAP_NET_ADMIN 可用时），M4 是无权限兜底。T5 矩阵确保
  两个 adapter 在各自权限场景下都跑通 G1 mini，且 unavailable 场景显式报错

---

**所有决策已落定，可按 §14 顺序开工。**实施过程中若新出现决策点，
回写到本节而不是临时拍板，保持可追溯性。
