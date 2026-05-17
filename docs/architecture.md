# 架构

## 分层

```
┌─────────────────────────────────────────────────┐
│  Application (rendr 不感知协议)                  │
│  调用 rendr.Dial / rendr.Listen 拿到 net.Conn    │
├─────────────────────────────────────────────────┤
│  Migration Engine                                │
│  bridge 表、状态机、cleanClose 鉴别、zombie 保护  │
├─────────────────────────────────────────────────┤
│  Mode Layer (prime / bond / race)                │
│  路径选择、帧调度、重排去重、聚合                  │
├─────────────────────────────────────────────────┤
│  Path Layer                                       │
│  Path 抽象、质量探测、生命周期                     │
├─────────────────────────────────────────────────┤
│  Transport Adapters                               │
│  tcp_termination / tcp_repair / gvisor / quic /   │
│  udp_opaque                                       │
└─────────────────────────────────────────────────┘
```

## 接口边界

### 对应用

```go
type Conn interface {
    net.Conn
    // Paths returns the currently-attached path(s).
    Paths() []PathInfo
    // SetMode switches the operational mode; the runtime may reject
    // if the connection has already started using state incompatible
    // with the new mode (e.g. bond → prime is fine, race → bond is not).
    SetMode(Mode) error
}

type PacketConn interface {
    net.PacketConn
    Paths() []PathInfo
    SetMode(Mode) error
}

type Dialer struct {
    Mode      Mode
    Paths     []PathSpec      // candidate paths
    Hysteresis float64        // prime: switch threshold
    Dwell      time.Duration  // prime: min stay on a path
}
```

应用拿到的 `Conn` 在迁移期间**不会**触发任何错误。这是核心承诺。

### 对 transport adapter

```go
type Transport interface {
    Name() string
    DialPath(ctx context.Context, spec PathSpec) (PathConn, error)
    Probe(ctx context.Context, spec PathSpec) (PathQuality, error)
}

type PathConn interface {
    io.ReadWriteCloser
    Quality() PathQuality
    OnDeath(func(error)) // notify migration engine
}
```

`PathConn` 是单条路径的实例，对外承诺**字节流可靠** OR **数据报顺序无关**（按 transport 性质）。它的死亡由 OnDeath 上报，不由 Read/Write 错误暴露给上层（避免 hy2scale "传输错误被误判为 EOF" 的覆辙）。

### 对 mode layer

```go
type Scheduler interface {
    // Submit accepts a frame from the engine and decides which
    // PathConn(s) carry it. For bond it splits; for race it
    // duplicates; for prime it picks one.
    Submit(frame []byte, seq uint64) []PathConn
    // OnRecv hands the engine the reassembled / deduped stream.
    OnRecv(frame []byte, fromSeq uint64, fromPath PathConn)
}
```

## 帧格式（控制平面 v0）

每个 rendr 帧前置 8 字节头：

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|VER|T|F|       FLAGS         |          SEQ (low 16 bits)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SEQ (high 32 bits)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `VER` 2bit — 协议版本，初始 0
- `T` 1bit — 0=DATA, 1=CTRL
- `F` 1bit — 0=middle frame, 1=last frame of the message（仅 reliable 模式有意义）
- `FLAGS` 12bit — 模式相关
- `SEQ` 48bit — 全局帧序号（per-Conn，单调递增）

控制帧类型（T=1, FLAGS 的低 8 位）：

| code | name | 方向 | payload |
|------|------|------|---------|
| 0x01 | HELLO | both | flow_id (16B) + caps (4B) |
| 0x02 | MIGRATE_NOTIFY | both | new_path_id (4B) |
| 0x03 | PATH_QUALITY | both | rtt_us (4B), jitter_us (4B), loss_pp (2B) |
| 0x04 | HEARTBEAT | both | timestamp (8B) |
| 0x05 | BYE | both | reason (1B) |
| 0x10 | BRIDGE_TAG | only on path-bring-up | bridge_id (16B) |

## Bridge 与 Flow

- **Bridge**: 一条 rendr Conn 的服务端侧入口；保存 flow_id → (在线路径集、scheduler 状态)
- **Flow**: 跨整个连接生命周期的逻辑标识，由首次握手分配，16B
- 迁移即"flow_id 不变，新增/移除附着在它上面的 path"

## 不变量

1. **flow_id 在 Conn 生命周期内不变**：迁移、模式切换、路径替换都不影响
2. **SEQ 全局单调**：所有帧（数据 + 控制）共用一个序号空间
3. **每个 path 上的字节都自带 SEQ**：不依赖路径的有序性
4. **mode 切换需双端确认**（CTRL 帧 + ACK），单端切换非法

## xray 集成形态

rendr 作为独立 Go 模块发布，并提供 `pkg: rendr/xray` 子包，把核心引擎封装为 xray-core 兼容的 transport：

```go
// rendr/xray
func NewRendrDialer(cfg *RendrTransportConfig) (internet.Dialer, error)
func NewRendrListener(cfg *RendrTransportConfig) (internet.Listener, error)
```

`RendrTransportConfig` 在 xray protobuf 体系中作为新 stream settings 类型注册，配置项：
- 模式（prime / bond / race）
- 候选 paths（每条 path 自身是某种 xray transport：tcp / quic / mkcp / ws / grpc / h2 ...）
- prime 参数（hysteresis / dwell / cooldown）

rendr **不是定义新的 wire protocol 的 transport，而是 transport-of-transports**：它包装 xray 已有 transport，叠加迁移能力。详见 `docs/xray-integration.md`。

## 平台差异

| 能力 | Linux | macOS | Windows |
|------|-------|-------|---------|
| tcp_termination (M1) | ✅ | ✅ | ✅ |
| TCP_REPAIR (M2) | ✅ (≥3.5) | ❌ | ❌ |
| gvisor netstack (M3) | ✅ | ✅ | ⚠️ 慢 |
| QUIC migration (M4) | ✅ | ✅ | ✅ |
| UDP opaque (M5) | ✅ | ✅ | ✅ |

非 Linux 平台缺失 TCP_REPAIR 后，TCP 单端无损迁移走 gvisor。

## 测试钩子

- 每层暴露 `_test.go` 友好的注入点：fake transport、可控质量 mock、可触发的迁移
- chaos harness 不进 `rendr` 主包，独立在 `chaos/` 模块
