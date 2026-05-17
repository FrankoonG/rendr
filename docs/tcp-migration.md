# TCP 无损迁移：方案与取舍

## 难点本质

TCP 的状态机有大量隐式状态：SEQ/ACK 编号、send 重传队列、recv 乱序队列、拥塞窗口、RTO 计时器、SACK 计分板、timestamp、PAWS、Nagle/cork、SO_RCVLOWAT、urgent pointer……要"无损"迁移，就要把这些**全部**搬到新位置，而且对端不能感知任何异常（不能收到 SEQ 跳跃、不能收到 RST、不能因 keepalive 探测被踢）。

加上 NAT / conntrack 实际部署中无处不在，五元组一变 conntrack 就丢，连搬迁机会都没有。

## 方案 A：双端 rendr + 用户态 bridge（M1）

**思路**：两端都跑 rendr。应用看到的 fd 是 rendr 提供的本地连接（unix socket / loopback / net.Pipe），rendr 内部把数据通过"承载路径"传输。"承载路径" 是 rendr 自己选的（TCP、QUIC、或任何 byte stream），它死了换一条就行，对应用 fd 完全无感。

**优点**：
- 完全用户态，零内核依赖，跨平台
- "迁移" 退化为"换底层 PathConn"，复杂度低
- hy2scale streamBridge 已经验证可行

**缺点**：
- 性能上限受限于 loopback / pipe（仍可到几 Gbps，对大多数场景够用）
- 两端都得跑 rendr——纯外部应用作为对端时不可用

**结论**：M1 选这个，是基线，必须先有。

## 方案 B：单端 rendr + Linux TCP_REPAIR（M2 研究）

**思路**：rendr 只在一端运行。把"被迁移"那条对外 TCP 的状态完整保存（TCP_REPAIR），在新地点重建一个 socket，restore 状态，从新地点继续发包。对端是普通 TCP，不感知。

### TCP_REPAIR 能拿到什么

Linux ≥ 3.5。`setsockopt(SOL_TCP, TCP_REPAIR, &on)` 之后该 socket 进入"修理模式"：

| getsockopt | 内容 |
|------------|------|
| TCP_REPAIR_QUEUE + TCP_QUEUE_SEQ | 当前 send / recv 队列的下一个 SEQ |
| TCP_REPAIR_QUEUE=SEND + recv() | dump 未确认的 send 队列字节 |
| TCP_REPAIR_QUEUE=RECV + recv() | dump 已收但未交付的 recv 队列字节 |
| TCP_REPAIR_OPTIONS | mss、wscale、sack、timestamp 标志 |
| TCP_REPAIR_WINDOW | snd_wnd / rcv_wnd / max_window / rcv_wup |
| TCP_TIMESTAMP | timestamp value |
| TCP_INFO | 拿到 rtt 估计供新端 RTO 用 |

`set` 反向：用同样的接口把状态灌回新 socket。然后 `setsockopt(TCP_REPAIR, &off)` 退出修理模式，socket 立即可用。

### 关键挑战

1. **五元组一致**：新 socket 必须 bind 到原源 IP + 原源端口，connect 到原目的 IP + 原目的端口。`IP_TRANSPARENT` + `SO_REUSEADDR` + `IP_BIND_ADDRESS_NO_PORT` 配合。

2. **conntrack 不能丢表**：迁移过程中如果路径切换让出口 NAT 变了，conntrack 就乱了。要么走 `--notrack` 绕过，要么保证对端见到的源 IP 不变（通过 wireguard / tun 之类的稳定虚拟出口）。

3. **send 队列重发**：迁移完成后必须把 dump 出来的 send 队列字节重新 write 进去，确保 SEQ 连续。

4. **窗口同步**：snd_wnd / rcv_wnd 必须重建，否则迁移后第一个包会被对端按窗口外丢弃。

5. **timestamp PAWS**：如果对端开了 timestamp 且新端 timestamp 倒退，PAWS 把所有包当成回放丢掉。`TCP_TIMESTAMP` setsockopt 是这里的关键。

6. **权限**：需要 CAP_NET_ADMIN。容器场景必须 `--cap-add NET_ADMIN`。

7. **kernel 版本**：≥ 3.5 出基础接口，≥ 4.5 才完整。4.x LTS 之前的发行版要测。

### 应用 fd 透明性

应用如果一直 `read(fd)`，迁移期间 read 会怎样？

- 进入 repair 模式之后，read 会被阻塞或返回 EAGAIN（取决于 socket 设置）
- 这与 hy2scale "应用层 fd 不变" 的承诺**不完全等价**：应用可能感知到短暂阻塞
- 但应用看到的 fd 编号不变、不会收到 EOF / RST，"无损" 在这个意义上成立

如果需要绝对透明（连阻塞都不能有），方案 B 单独不够，必须叠加方案 A 的"本地 fd + 后端 socket"两层结构：
- 应用拿到 rendr 提供的 fd（unix socket）
- rendr 后端用 TCP_REPAIR 维护到对端的真实 socket
- 迁移期间 rendr 在 app fd 上继续 ACK / 缓冲，对外那条 socket 在切换

### 已有参考

- CRIU 的 tcp/criu-tcp.c：完整的 dump/restore 实现（用于整进程迁移）
- Netflix 的几个公开 talk 提到过 TCP_REPAIR 用于服务实例搬迁
- `iproute2` / `ss --repair` 在内部用 TCP_REPAIR

## 方案 C：gvisor netstack 用户态 TCP（M3 fallback）

**思路**：用 `gvisor.dev/gvisor/pkg/tcpip` 在用户态跑完整 TCP 栈。rendr 完全掌控 TCB，序列化整个 endpoint，丢到新位置反序列化继续。

### 优点

- 跨平台（Linux/macOS/Windows 都跑）
- 不依赖 CAP_NET_ADMIN
- TCB 状态 100% 可见可控
- 已有 hy2scale TUN compat 模式的实战经验

### 缺点

- 性能：用户态 TCP 比内核 TCP 慢 2-5x（gvisor benchmark 数据）
- 实现复杂度高：需要从 NIC 拿到 raw frame / 配 tun，把 IP 包喂进 netstack
- 内存：每个 endpoint 占用比内核更多

### 适用场景

方案 B 在目标平台不可用时（macOS/Windows，或 Linux 但没 CAP_NET_ADMIN）的兜底。

性能可接受时（< 1 Gbps），它是单端透明迁移的唯一通用解。

## 方案 D（不投入）：CRIU

整进程迁移。粒度太粗，不能"只迁移一条连接而保持进程其他状态"。明确放弃。

## 推荐路线

1. **M1 先做方案 A**：双端模型，能立刻 demo
2. **M2 spike 方案 B**：单端场景的 POC，验证 TCP_REPAIR 在生产容器内可用
3. **M3 实现方案 C**：单端 + 非 Linux 平台的 fallback
4. 方案 B 与 C 二选一暴露给上层，方案 A 始终是双端模式默认

## TCP_REPAIR POC 检查表

做 M2 spike 时验证：

- [ ] kernel ≥ 4.5 的 dump → restore 来回，对端不感知 RST
- [ ] 容器内有 CAP_NET_ADMIN 时可用
- [ ] 容器内无 CAP_NET_ADMIN 时明确报错（不静默退化）
- [ ] 迁移期间 conntrack 行为：源 IP 不变时 ok，源 IP 变时如何处理
- [ ] timestamp / PAWS 不挂
- [ ] 长连接 30 分钟，迁移 60 次，对端单方面累计丢包 < 0.1%
