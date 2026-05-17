# xray 兼容性自检清单 (M0 deliverable)

这是 rendr 在被 xray-core 当作 transport 调用时的**核心层假设清单**。任何被勾掉的项都必须在 M9 集成之前被独立验证。读这个清单的目的：让"rendr 能不能挂进 xray"在 M0 阶段就成为可逐项判定的问题，而不是 M9 才发现绑死。

## A. 接口契约

- [ ] xray `internet.Dialer` 期望返回的是 `net.Conn`；rendr.Conn 实现 net.Conn → 直接满足。
- [ ] xray `internet.Listener` 期望 Accept 返回 net.Conn；rendr.Listener.Accept 返回 rendr.Conn → 满足。
- [ ] xray 调用方对 Conn 的 Read/Write 错误的解读：rendr 承诺迁移期不返回错误（CLAUDE.md hard rule #1）。需在集成 wrapper 里**显式 doc**这条，避免 xray balancer 把"没数据"误判为路径异常。
- [ ] xray `mux` / `vmess` 等协议层是否依赖底层 EOF 的及时性？rendr 在迁移挂起时 Read 会阻塞 ≤ MigrationBudget(90s)。需要确认 xray 协议层对这种阻塞的容忍度。

## B. 路径生命周期

- [ ] rendr 候选 paths 自身是 xray transport（tcp / mkcp / quic / ws / grpc / h2）。需要适配层把 xray internet.Dialer 当作 rendr.Transport.DialPath 的实现。
- [ ] xray transport 的 SecuritySettings (TLS, ECH) 必须被 rendr Pathspec.Opts 透传，不能被 rendr 重新封装一遍。
- [ ] 多个候选 path 共享相同的"目标 endpoint"（host:port）合法吗？对 vmess server-side 鉴权来说，多 path 多次握手会被认为是多个用户吗？需要确认。

## C. 协议版本与升级

- [ ] proto.Version 在 wire 上是 2 bit。M0 起 == 0。升级到 1 时，xray 侧的 RendrTransportConfig protobuf 也要 bump version field。**不允许只 bump 一边**。
- [ ] xray-rendr 集成的 proto 协议号（HELLO / MIGRATE_NOTIFY / ...）与 rendr 独立运行时**必须**一致。这是同一个 wire format，不存在"xray 专属变体"。

## D. 双端要求

- [ ] M1 拓扑要求两端都跑 rendr。xray 客户端 + xray 服务端都必须加载 rendr transport。**纯单端 rendr + 远端裸 vmess 的拓扑在 M1 不支持**。M3/M4（TCP_REPAIR / gvisor）成功后可解锁单端。
- [ ] xray balancer / outbound 选择策略与 rendr prime 模式的冲突：xray 自己也会切线（BalancerObject），rendr 也会切 path。需要文档化：建议把 xray 的 balancer 关掉，让 rendr 做唯一的 path 选择者。

## E. 资源与并发

- [ ] xray 通常一进程多 outbound、多 inbound。rendr 引擎是否 per-Conn 状态？是。Bridge 表是 per-Listener（即 per-inbound）的；多 inbound 各自独立。
- [ ] xray 中 mux.Cool 会复用一条底层 conn 跑多个虚拟 stream。rendr.Conn 是单逻辑 stream；mux 在 rendr 之上由 xray 自己做即可。**rendr 不需要支持多路复用语义**。
- [ ] 帧调度 goroutine 数量上限：每个 rendr.Conn 启动 1 个发送 goroutine + 1 个接收 goroutine + N 个 PathConn 读 goroutine（N = active paths）。1k 并发连接 → ~3-10k goroutine。可接受。

## F. 测试覆盖

- [ ] G1-G5 必须先在**裸 rendr**（不接 xray）跑通。这是 success-criteria.md 的硬约束。
- [ ] G1-G5 在 xray-rendr 集成形态下**重新跑一遍**（M9 验收）。任何"独立通过但集成失败"必须查清根因，不能"算了"。
- [ ] xray 自身的回归测试套件（vmess/vless/trojan over rendr-over-tcp/quic）作为 release 门禁。

## G. 不在 rendr 范围内的事

- [ ] xray 配置文件管理：不做。embedder 负责。
- [ ] xray BalancerObject 等价物：不做。rendr 提供 prime 模式作为替代或互补。
- [ ] xray Routing 决策：不做。rendr 只看到一条逻辑 Conn。

## 验收

M0 阶段不要求任何一项是 ✓。M0 要求的是：**这张表上每一项都能被 rendr 团队具体说出"将来怎么验证"**，而不是含糊地"应该能行"。
