# xray 集成方向

## 定位

rendr 的最终交付形态是**可被 xray-core 直接调用的迁移层**。独立的 G1-G5 金标准先在 rendr 自带的 harness 里跑通，跑通后再封装成 xray 兼容的接口、回归 xray 自身的协议套件（VMess、VLESS、Trojan、SS 等）。

这意味着 rendr 的公共 API 设计要从一开始就考虑两件事：
1. **xray internet.Dialer / Listener 接口**：rendr 必须能作为 xray 的一种"transport"接入
2. **xray Balancer 协议**：rendr 的 prime 模式逻辑要与 xray BalancerObject 的 selector 语义可对齐或可替换

## xray 关键接口锚点

xray-core 中（v25.x 主线）相关位置：

| 子系统 | 位置 | 用途 |
|--------|------|------|
| transport.internet.Dialer | `transport/internet/dialer.go` | 出站拨号；rendr 包装一层 |
| transport.internet.Listener | `transport/internet/tcp/hub.go` 等 | 入站监听；rendr 提供一种 network |
| transport.internet.StreamConfig | `transport/internet/config.proto` | 配置；rendr 加新 transport 类型 |
| router.BalancerObject | `app/router/balancing.go` | 多 outbound 平衡；rendr prime 模式可对接 |
| common.net.Connection | `common/net/connection.go` | net.Conn 拓展；rendr Conn 必须满足 |

### internet.Dialer 形态

xray 期望的拨号器签名（简化）：

```go
type Dialer interface {
    Dial(ctx context.Context, dest net.Destination) (Connection, error)
    Address() net.Address
}
```

rendr 提供的 dialer 工厂：

```go
// pkg: github.com/<user>/rendr/xray
func NewRendrDialer(cfg *RendrTransportConfig) (internet.Dialer, error)
```

`RendrTransportConfig` 在 xray 的 protobuf 体系里注册一个新的 stream settings 类型（如 `transport_settings.rendr`），里面携带：
- 模式（prime / bond / race）
- 候选 paths（每条 path 自身又是某种 xray transport：tcp / quic / mkcp / ws / grpc）
- prime 参数（hysteresis / dwell / cooldown）

也就是说，**rendr transport 是 transport-of-transports**：它本身不定义 wire-level 协议，而是组合若干 xray 已有 transport，叠加迁移能力。

### Balancer 对接

xray BalancerObject 本来按 outbound tag 选 outbound（按规则、按 priority、按 random / leastPing），是 connection-level 而非 mid-stream。rendr prime 模式打破这一点：

两种集成路线：

1. **Adapter 模式**：保留 xray BalancerObject 不变，rendr 作为一个 outbound 内部自己做 mid-stream 迁移。balancer 选了 rendr-outbound 后，rendr 在内部多 paths 之间迁移，对 balancer 不可见
2. **Plugin 模式**：扩展 xray BalancerObject，让 selector 决策能在已建立的 outbound conn 上下发 "migrate to X" 信号。需要改 xray 上游

**默认走 Adapter 模式**。Plugin 模式仅在 Adapter 无法满足某些场景时再讨论。

## 数据流

```
应用 → xray 入站 → xray router → outbound[rendr]
                                       ↓
                              rendr migration engine
                                       ↓
                       [path-tcp][path-quic][path-ws]...
                                       ↓
                              对端 xray 入站 (或裸 server)
                                       ↓
                                  目标 dest
```

入站侧也可以装 rendr 作为接受端 listener（如果对端用 rendr dialer），双端配对时获得完整 G1-G5 能力。

## 协议兼容

- rendr 自己的控制帧（HELLO / MIGRATE_NOTIFY / HEARTBEAT 等，见 `docs/architecture.md`）跑在每条 path 的应用层
- 不与 xray 的 protocol 协议（vmess/vless/trojan）冲突——rendr 在 transport 层下面
- 应用层协议 → rendr 帧 → underlying transport（tcp/quic/ws/...）

加密由谁负责？

- 默认：底层 xray transport 自己加密（tls / reality / vless 的 xtls 等）
- rendr **不加密自己的控制帧**，因为 path 已经在 TLS 之下
- 如果 path 是裸 TCP（无 TLS），rendr 控制帧也不加密——这是配置选择，由用户负责

## 实施次序

xray 集成放在 G1-G5 金标准通过之后（M9 阶段或独立分支）。原因：

1. 先在独立 harness 跑通 G1-G5 才能证明引擎本身没问题
2. 跑不通就改引擎，跑通后再封装。否则 xray 那层的复杂度会让 debug 噩梦
3. xray 集成后的回归测试覆盖更广（vmess/vless/trojan over rendr），但替代不了 G1-G5

### 集成阶段拆分

| 阶段 | 内容 |
|------|------|
| X1 | rendr 作为 xray 模块构建（go module path、import 路径） |
| X2 | 注册 stream settings 类型 + proto 定义 |
| X3 | 实现 internet.Dialer / Listener |
| X4 | path 子配置：嵌套引用 xray 已有 transport 配置 |
| X5 | 端到端 vmess-over-rendr-over-tcp+quic 验证 |
| X6 | BalancerObject 对接（Adapter 模式） |
| X7 | xray 主线回归测试（vmess/vless/trojan/ss 全部 over rendr） |

## 与 xtls / reality / 截断防御的关系

xtls / reality 是 xray 自身在 path 层的安全机制。rendr 不替代也不重新实现这些。每条 path 可以独立挂 reality（path A = reality+tcp，path B = reality+quic），互不影响。

迁移期间 reality 状态？

- reality 是握手时一次性的，连接建立后是普通 TLS
- 迁移导致 path 切换 = 在新 path 上新建一条 reality 握手
- 新 path 起来后，rendr 才会把流量切过去；旧 path 的 reality 连接最后 close
- 应用看到的 net.Conn 不变，但底下其实是"两条 reality session 在交接"

这与 rendr 在非 xray 场景下的行为一致——rendr 只关心 path 上的 byte stream / datagram，不关心它的安全外壳。

## fork vs 上游

短期：rendr 作为独立 Go 模块，xray 用户在自己的 fork 里 wire 进去。

长期：如果 G1-G5 在 xray 集成形态下也稳了，可以提交 xray 上游 PR 把 transport 类型注册进去。这一步需要：
- 完整的 protobuf 定义
- 上游测试套件兼容
- 上游维护者 review

不强求合并，rendr 独立 useful 即可。

## 不做的事

- 不 fork xray 整库做"魔改版"。rendr 仅作为 Go 模块挂接
- 不重写 xray router、不替换 xray dispatcher
- 不引入对 xray 内部非公开 API 的依赖（除非走 vendor patch）
