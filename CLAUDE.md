# rendr — Project Instructions

## 新 session 入场动作（强制）

任何会话开始时，**无论用户首条消息是什么**（哪怕只说"开始"、"从 plan.md 开始"、"继续 M1"），必须先按顺序 Read：

1. `docs/success-criteria.md` — 金标准 G1-G5；不知道判据就不能开工
2. `docs/plan.md` — 当前 milestone 位置与判退条件
3. 与当前任务直接相关的专题 doc（按下表选择）：

| 任务关键词 | 必读 docs |
|-----------|----------|
| 接口 / 协议 / 帧格式 | `docs/architecture.md` |
| TCP 迁移 / TCP_REPAIR / gvisor | `docs/tcp-migration.md` + `docs/architecture.md` |
| QUIC / UDP / ConnID / flow-id | `docs/udp-quic-migration.md` + `docs/architecture.md` |
| prime / bond / race / 路径选择 | `docs/modes.md` |
| 测试 / chaos / 长驻 / 限速 | `docs/testing.md` + `docs/test-hosts.md` |
| xray transport / 集成 / balancer | `docs/xray-integration.md` |
| 任何"为什么这样做" / "历史教训" | `docs/lessons-from-hy2scale.md` |

**不能跳过 1 和 2 直接进实现**。哪怕用户明确说"跳过文档直接写代码"，也要先读 success-criteria.md 和 plan.md，再决定是否还要读其他——这两份是判定"实现是否完成"的唯一依据，跳过等于放弃验收。

读完之后再开始与用户对话推进任务。本节优先级高于用户的"快开始"诉求。

## 项目目标（不可变更）

rendr 是一个独立的、可被嵌入到任意上层应用的**连接无损迁移框架**。它只解决一件事：当承载某条应用连接的底层路径变化（断开、降级、被替换）时，应用层不感知任何中断，连接 fd 保持不变，数据继续流。

**最终交付形态**：可被 xray-core 直接调用的 transport 模块。独立 G1-G5 金标准（见 `docs/success-criteria.md`）先通过，然后封装为 xray-compat 形态再验证一遍。

**金标准（不可妥协）**：
- TCP↔TCP 与 QUIC↔QUIC 协议同构的连接无损迁移
- 典型场景：≥1 GB 文件下载，中途路径强制迁移多次，**传输不中断、不暂停、用户无感**，文件 SHA-256 与原文件一致
- 完整判据见 `docs/success-criteria.md` 的 G1-G5

**显式不在范围内**：
- 不做 mesh / peer discovery / 多节点拓扑（那是上层应用的事）
- 不做 Web UI、配置管理、运维面板
- 不做 TCP↔UDP 跨协议迁移（README 已明确放弃）
- 不做内置代理协议（SS、Trojan、Hysteria 等）；rendr 提供 Conn / PacketConn API，由调用方决定协议
- 不 fork xray 整库做"魔改版"。rendr 作为独立 Go 模块挂接

## 三种模式（README 已定义）

- **prime**: 稳定优先。在所有可用路径中选延迟+抖动最小的，超阈值后迁移
- **bond**: 速度优先。多路径帧级聚合，单连接吞吐叠加
- **race**: 不计代价稳定。每包/帧同时发到所有路径，先到先用、后到丢弃

三种模式共用同一套迁移引擎与路径质量层。

## 技术选型默认值

- **语言**: Go（与 hy2scale 生态一致；quic-go、gvisor、google netstack 均 Go 可用）。Rust 仅在出现 Go 无法胜任的边界情况时讨论
- **TCP 迁移路径**:
  1. 首选研究方向：Linux `TCP_REPAIR` + 自管 SEQ/ACK，配合两端 rendr 终结 TCP
  2. fallback：gvisor netstack 在用户态实现 TCP，序列化 TCB
  3. 不投入：CRIU 整进程迁移（粒度太粗，与"单连接迁移"的目标不匹配）
- **UDP/QUIC 迁移**: 直接利用 RFC 9000 §9 Connection ID。不重新发明
- **不透明 UDP（非 QUIC）迁移**: 通过 rendr 引入的 flow-id 头部承载，迁移操作针对 flow-id 而非五元组

## 硬规则（违反必回滚）

1. **TCP 迁移对应用透明**：应用看到的 net.Conn 在迁移过程中**不能**触发任何可观察的 reset / SO_ERROR / read-zero / write-error。如果做不到透明，该实现就不是迁移而是重连
2. **传输层错误 ≠ 应用层 EOF**：这是 hy2scale 反复踩坑的根因。`quic.IdleTimeoutError`、`HandshakeTimeoutError`、`ApplicationError`、`TransportError` 即使表面 `net.ErrClosed`，也必须分类为"需要触发迁移"。`io.EOF / io.ErrUnexpectedEOF` 是干净关闭，**不**触发迁移
3. **默认不安装主动迁移触发器**。"长时间静默就 rebind" 之类的策略会误杀慢速合法传输。Trigger 接口保留，默认空集
4. **迁移预算 90s**：路径完全丢失后，连接最多挂起 90 秒等待新路径；超过则真正 close。这个数字直接来自 hy2scale 的混沌测试结论，不要随手改
5. **zombie 保护**：连续 2 次迁移完成但没有任何 payload 通过，认定远端会话已死，停止重试。配合 30s cooldown 衰减计数器
6. **每跳独立**：多跳路径中每一跳是独立的迁移单元，不做端到端级联迁移协议。这是 hy2scale Phase 2 验证过的形态
7. **协议版本化**：任何写到线上的字节顺序、握手字段、控制帧都必须带版本号；任何模式（prime/bond/race）的线上协议改动必须 bump

## Git 身份（强制）

- 本仓库所有 git 操作（commit、push、PR、issue、gh CLI）**必须**使用 `FrankoonG` 账号
- 提交前确认 `gh auth status` 显示 active 账号是 FrankoonG；不是的话先 `gh auth switch -u FrankoonG`
- 不要写入 `user.name` / `user.email` 到 global config——只允许在仓库局部设置
- pre-commit / sign 出错时**先确认身份**再排查
- 与其他 GitHub 账号（如 Score2 全局默认）共存时，每次 push 前显式核对

## 协作与工作流

- 任何"基于实验得出的结论"的修改，必须有可复现的测试用例（脚本进 `test/`，目录已 gitignored）
- chaos 测试是发布门禁：不通过混沌测试的 commit 不能进 main
- 单路径基线必须先通过，再做多路径合成。"composite 通过 ⇒ baseline 通过" 不成立
- 长驻测试 ≥10 分钟才能发现 NAT 60s/120s 等真实超时；短测不算
- 带宽限速是 resilience / recovery 类测试的必备前置——docker 默认网络太快，跑出来的数据没意义

## Git 与发布

- 分支命名：`vX.Y.Z`（新版本主线），`vX.Y.Z-<purpose>`（针对已发布版本的补丁）。沿用 hy2scale 的约定
- main 上不直接开发；每个版本在自己的分支上做完、PR 合入、tag
- 永远不要 `git add -f` 跳过 .gitignore；临时文件去 `test/` 或 `docs/`
- 不要全局通配符 .gitignore（`*.log` `*.tar.gz` 之类）会误伤合法文件

## 测试主机

参见 `docs/test-hosts.md`。摘要：
- `root@10.130.32.32` — demo VM，与 `10.130.32.0/24` 内网直通
- `root@172.20.0.107` — 真实 DNS 污染 ISP 环境的 Ubuntu，可达 `10.130.32.0/24`，可恢复快照、可破坏性实验
- `root@176.97.73.24` (JPB) — 海外节点
- `aub.tular.io` (AUB) — 海外节点（host network）
- iKuai v3 `10.130.32.40`、v4 `10.130.32.41` — 路由器形态客户端测试

均用默认 SSH key 直连（除 iKuai 用户名/密码）。详细见 `docs/test-hosts.md`。

## 写作风格（docs / 提交信息）

- docs 是给后来人看的，可以有篇幅；但必须有结构、能跳读
- 不写"我们曾经如何如何"——只写"现在为什么这样，违反会怎样"
- 提交信息英文，subject ≤ 70 字符
- 不要为了凑节而写"Background / Motivation / Conclusion"三段式，能用一段说清的就一段

## 关键文档索引

- `docs/plan.md` — 里程碑与排期
- `docs/architecture.md` — 引擎分层、接口边界
- `docs/tcp-migration.md` — TCP_REPAIR / gvisor 路线对比与选择
- `docs/udp-quic-migration.md` — QUIC ConnID + 不透明 UDP flow-id 方案
- `docs/modes.md` — prime / bond / race 的规约与失败语义
- `docs/lessons-from-hy2scale.md` — 来自 hy2scale 的、非显然的、必须遵守的工程经验
- `docs/testing.md` — chaos 测试方法论、长驻测试、带宽限速、复现门禁
- `docs/test-hosts.md` — 可调用的测试主机清单与连接方法
