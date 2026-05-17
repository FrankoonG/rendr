# M0 完成判据走查：如果跑 G1，每一层会发生什么

`docs/plan.md` 的 M0 完成判据是"能讨论'如果跑 G1，每一层会发生什么'全流程，无未解决疑点"。本文是那份走查，写下来本身就是验收。任何回答里出现"待定"的，M0 没完。

G1 重述：≥1 GB 文件传输，在 30% / 50% / 70% 各强制触发一次路径迁移，零中断、零暂停、SHA-256 一致，总耗时 < 基线 × 1.1。

## 拓扑（M1 形态）

```
[uploader 进程] --unix sock--> [rendr client] -- pathA(TCP) --> [rendr server] --unix sock--> [downloader 进程]
                                              -- pathB(TCP) --/
```

uploader 把文件以一条 net.Conn 写入；downloader 从对端 net.Conn 读出。中间所有路径切换由 rendr 内部完成。

## 一次 1 GB 传输的逐层故事

### 0. 应用层（uploader / downloader）

- uploader: `Write(buf)` 反复调用直到 1 GiB 写完，最后 `Close()`
- downloader: `Read(buf)` 反复调用直到 io.EOF，校验 SHA-256
- 应用看到的 net.Conn fd 编号在整个过程中**不变**。这是 G2 的同种判据延伸。

### 1. rendr 公共 API (pkg `rendr`)

uploader 拿到的 `rendr.Conn` = 实现 net.Conn 的内部类型 `*engineConn`。`Write` 把字节切块（≤16 KiB / 帧），交给 engine 的发送 ring；engine 给每个块分配一个全局 48-bit SEQ。

发送方向到这里就结束："数据已交给 engine，不返回错误"。读方向反向。

### 2. Migration Engine (`internal/engine`)

engine 持有：
- `BridgeState`: 当前是 BridgeActive
- send ring buffer: 待发帧
- recv reorder buffer: 待按 SEQ 投递的帧
- 已附着 paths 的集合

正常态：engine 把每帧交给当前模式 Scheduler（M1 阶段先实现 prime + 单 path），Scheduler 返回 PathConn 列表（在 prime 下是单元素），engine 把帧用 proto.Header 包好后 Write 给那条 PathConn。

`MigrationBudget=90s` 在 BridgeMigrating 时计时；BridgeActive 不消耗。Zombie 计数器随成功 payload 通过被清零。

### 3. Mode Layer (M1 单 path 时退化)

prime 模式：永远返回当前唯一活跃 path。在 G1 流程中 pathA 是首选。bond/race 在 M7/M8。

### 4. Path Layer

`PathConn` 是 transport 包定义的接口。M1 实现 = TCP 终结：rendr server-side bind 一个 TCP listener，client 侧 dial 进来，TLS（可选）建立后即为一个 PathConn。

每个 PathConn 暴露 `Quality()` 返回最近探测的 RTT/Jitter/Loss。M1 阶段 quality 可以是占位值（M6 才让 prime 真用它）。

### 5. Transport Adapter (TCP termination, M1)

读：从 TCP 字节流里**按 2 字节大端长度前缀**反复读出 frame；解 8 字节 header；交给 engine recv 路径。

写：engine 给的 frame 前置 2 字节长度后 syscall write。

错误：任何 Read/Write 错误经 `transport.Classify(err, quiesced, byeSeen)` 分类，CleanClose 才 propagate EOF；其他通过 `OnDeath(CauseTransportError, err)` 通知 engine。

## 迁移触发：在 30% / 50% / 70% 各一次

测试 harness 调用 engine 的内部触发器（M1 暴露给测试的迁移注入点）。流程：

1. engine 看到 trigger，开始 path attach 流程：拨号 pathB（已经预拨号的话直接切）
2. pathB attach 完成，engine 发 `MIGRATE_NOTIFY{NewPathID=pathB.id}` 控制帧给对端
3. engine 在 send ring 上切换：从此刻起新帧走 pathB
4. 关键 SEQ 状态：发送方下一帧 SEQ = 上一帧 SEQ + 1；pathB 是个崭新字节流，但 SEQ 是 per-Conn 全局的，不重置（架构 invariants #2/#3）
5. 接收方 reorder buffer 按 SEQ 投递，pathA / pathB 顺序无关
6. pathA 不立刻关：engine 在 pathA 上看到所有已发但未 ack 的 SEQ ack 完后才让 pathA 走 cleanClose（M1 用 control plane BYE）
7. **应用看不到任何错误**：uploader.Write / downloader.Read 在切换瞬间最多被阻塞几毫秒（取决于 send buffer），但**不返回 error，不返回 0 字节**

### 关键不变量验证

- SEQ 单调：pathA 发到 seq=N 切到 pathB；pathB 上首帧 seq=N+1。验证：测试 harness 抓双 path 的 wire dump，合并按 seq 排序应为连续整数序列。
- flow_id 不变：客户端 HELLO 时分配 16B flow_id，pathA / pathB 上的 BRIDGE_TAG 都用同一个 flow_id。
- 应用 fd 不变：测试在 uploader / downloader 进程内每秒打印 `fileno(conn)`；G1 通过的判据之一就是这个不变。

## 边界场景的回答

### Q1: pathA 在迁移前传完的字节如何不丢？

答：pathA 上的写是 TCP，TCP 自身有 ack 重传。engine 不在 pathA 上启用 BYE 直到本地 send buffer 排空且收到对端 ack 当前最大 SEQ 的 PATH_QUALITY 心跳。这套机制 = "drain"，由 engine BridgeState 转换条件控制。

### Q2: pathA 突然死了（G4 场景）而不是有计划迁移呢？

答：transport 层的 OnDeath 触发，cause=TransportError。engine 进入 BridgeMigrating；如已存在 pathB 则立即切换；否则启动 MigrationBudget(90s) 倒计时。在 budget 内任意 path 成功 attach 即恢复。budget 用完 → 关 Conn，应用层 Read 返回 ErrMigrationBudgetExceeded。

⚠️ 此时 pathA 上 in-flight 但未 ack 的数据可能丢失。engine 在 BridgeMigrating 启动期间，会通过新 path 重发 [last_acked+1, last_sent] 区间的所有帧（基于 SEQ 重传窗口）。M1 buffer 上限 = 16 MiB 滑动窗口（按 BDP 上限估算；后续 M6 可调）。

### Q3: zombie 触发条件？

答：连续 2 次完成的迁移（attach 成功 + 切流完成）后，30s 内没有任何应用层 payload 通过（控制帧不算），engine 判定远端会话已死，关 Conn，应用层 Read 返回 ErrZombie。

### Q4: 应用 SetMode 在跑文件传输中途调用？

答：合法的 prime → bond 在 M8 之前会返回 ErrModeSwitchIllegal（M8 落地后再放开）。race → bond 永远非法（race 没维护 per-path 顺序，bond 需要）。

### Q5: 协议版本：rendr v0 server 收到 v1 client HELLO？

答：proto.DecodeHeader 解出 Version=1；engine 在 HELLO 处理时比较 == Version 常量；不等则发 BYE{Reason=ByeProtoVer} 后关 Conn，应用层 Read 返回 ErrPeerProtoVersion。

## M0 残余疑点

无。所有 G1 路径上的层都有了明确答案。M1 进入实现阶段。
