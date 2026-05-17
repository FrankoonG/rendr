# UDP / QUIC 无损迁移

## QUIC：用 RFC 9000 §9 原生支持

QUIC 在协议层就为连接迁移设计。**不要重新发明**，直接用 Connection ID 机制。

### 工作方式

- 每条 QUIC 连接有一个或多个 Connection ID（CID），与 4 元组解耦
- 客户端可以在新的 4 元组上发送同样 CID 的包，服务端按 CID 识别为同一连接
- 服务端通过 PATH_CHALLENGE / PATH_RESPONSE 验证新路径可用
- 之后 RTT 测量、拥塞窗口在新路径上重新校准（NEW path validation 完成后才完整切换）

### Go 实现选择

- **quic-go**：主流。0.40 起对客户端主动迁移的支持稳定，需要显式调用 `Connection.AddPath` / `SetPreferredPath`（API 名称随版本变化，spike 时再确认）
- **mvfst (FFI)** / **quiche (FFI)**：另两个稳定实现。FFI 复杂度大，除非 quic-go 有硬阻塞性能问题不考虑
- **lucas-clemente/quic-go**：注意上游 fork 状态，hy2scale 用的是 apernet 维护的 fork（带 hysteria 需要的修改）。rendr 用主仓即可

### 失败模式

- NAT rebinding：CID 让 server 知道是同一连接，但中间 NAT 把回程路径打死了。需要客户端主动 keepalive 探测以保活 NAT 表项
- middlebox 不喜欢同一 4 元组突然换 CID 长度：少见但存在
- 服务端无法主动发起迁移：协议设计偏客户端驱动；服务端只能"建议" preferred address

### 与 rendr 集成

rendr 的 QUIC transport adapter：
- 用 quic-go 建立一条 QUIC 连接，把它注册为单个"逻辑路径"
- 当 rendr 的 path layer 决定要换出口（不同 NIC、不同上游 ISP）时，调用 quic-go 的迁移 API
- 应用看到的 `Conn` / `PacketConn` 完全不变

QUIC 一条连接 = rendr 一条 path？还是 N 条 path？

**默认一条**：QUIC 已经内置多路径相关的草案（multipath QUIC），但还在 IETF 过程中。rendr 简化路线：一条 QUIC 连接对应 path layer 中的一个 path entry，需要叠加带宽时由 bond 模式起多条 QUIC 各自做 path。

## 不透明 UDP（非 QUIC）

WireGuard、IPsec、自定义 UDP 协议——它们的"会话状态"不在 rendr 这层能看见。但迁移仍然有意义：路径变了，让数据继续到达对端。

### flow-id 包头

rendr 在 UDP datagram 前置 8 字节：

```
+--------+----------------+
| ver(1) | flow_id (7B)   |
+--------+--------+-------+
| payload (变长)         |
+----------------+-------+
```

- 接收侧按 flow_id 查"虚拟会话"映射，把 payload 投递到对应的应用 socket
- 路径切换 = 同一 flow_id 的包从不同源 4 元组来，rendr 把映射条目里的"当前对端 4 元组" 替换

### 双端 rendr：完全可控

两端都跑 rendr 时：
- flow_id 由首次握手分配，对应用透明
- 应用拿到的 PacketConn 是 rendr 提供的，4 元组是固定的虚拟值
- 内部路径切换 = 改 flow_id → 实际 4 元组的映射，应用零感知

### 单端 rendr：尽力而为

对端是裸 UDP（普通 WireGuard 服务、L2TP 服务）：
- rendr 无法注入 flow-id 包头（对端不认）
- 只能让 rendr **不在迁移期间** 改变出口 4 元组
- 实现：rendr 维持一个稳定的"出口虚拟 4 元组"（通过 SNAT 到固定 IP/port），实际承载在底下切换

这种模式下 rendr 等于"做了 SNAT 的多路径出口"。应用层（WireGuard、IPsec）感知的对端不变，路径切换由 rendr 在底下做。

### NAT 与 keepalive

UDP NAT 表项默认 30-60s 超时。rendr 必须自己发 keepalive：
- 双端 rendr：HEARTBEAT 控制帧每 15s
- 单端 rendr：依赖应用自己的 keepalive（如 WireGuard 的 PersistentKeepalive=25）

## QUIC vs 不透明 UDP 取舍

| 场景 | 推荐 |
|------|------|
| 应用层用 HTTP/3 / 自研基于 QUIC 的协议 | 直接用 QUIC ConnID，rendr 当胶水 |
| 应用层是 WireGuard / IPsec | 不透明 UDP，双端 rendr 模式 |
| 应用层是裸 UDP echo / DNS | flow-id 头，双端 rendr |
| 对端不可控 | 单端 rendr SNAT 出口 |

## 测试矩阵

| 测试 | 目标 |
|------|------|
| QUIC ConnID 迁移 | 切换出口 NIC，连接不断 |
| flow-id 迁移（双端） | 改变中转节点，应用 PacketConn 不感知 |
| flow-id 高包率 | 100k pps 下 dedup 窗口不溢出 |
| UDP NAT keepalive | 60+ min 长驻不丢 |
| QUIC NAT rebinding | 30 min 内 NAT 表项故意失效，恢复 |
