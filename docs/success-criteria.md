# 成功硬约束

## 金标准（Gold Bar）

**TCP↔TCP 与 QUIC↔QUIC 协议同构的连接无损迁移**。

"无损" 的判定不是工程团队主观觉得"还行"，而是必须通过以下**所有**机械化测试：

### G1 — 大文件传输零中断

测试：传输一个 ≥1 GB 文件（rendr 两端 + 一个 iperf3 / scp / HTTP 下载）。在传输进行到 30%、50%、70% 时各强制触发一次路径迁移。

判据：
- 传输**不中断**（应用层不感知 EOF、error、reset）
- 传输**不暂停**（每秒吞吐曲线无 >500ms 的 0 值 gap）
- 总耗时相比无迁移基线增加 < 10%
- 文件 SHA-256 与原文件完全一致

### G2 — 长驻交互连接零感知

测试：在 rendr 两端建立一条 SSH（实际是 TCP 直通）或自定义 echo-loop（间隔 100ms，往返计时），运行 30 分钟。期间随机触发 ≥30 次路径迁移。

判据：
- 所有 echo 全部收到（0 丢失）
- 单次 echo 往返延迟 P99 < 基线 × 2，P99.9 < 1 秒
- 应用层 fd 编号在 30 min 内不变（无重连）

### G3 — 高包率 UDP/QUIC

测试：QUIC 单连接发送 100k pps（每包 ~1 KB，~1 Gbps），运行 5 分钟，期间触发 ≥10 次 ConnID 迁移。

判据：
- 0 包丢失（QUIC 重传不算"丢失"，但应用层必须收到全部）
- 迁移触发后 P95 RTT < 基线 × 2
- 吞吐恢复时间 < 200 ms

### G4 — 路径真死亡（非主动迁移）

测试：path A 上有活跃传输，把 path A 网络直接 `iptables -j DROP` 杀死（不通知 rendr）。同时存在备份 path B。

判据：
- 应用层不感知（不收到 EOF / error / reset）
- 切换到 path B 的等待时间 ≤ 5 秒
- 期间已发但未送达的数据通过 path B 全部送达

### G5 — 路径回归

G4 之后恢复 path A。

判据：
- path A 自动重新加入可用集合
- prime 模式下根据质量分决定是否切回（不强制切，但允许）
- 任何模式下不出现"路径恢复后异常重传 / 重排乱"

## REG-Phase1 基线（v0.1.0，commit bf3d7ff）

`docs/regression-suite.md` §14 step 4 要求把 phase 1 在 v0.1.0 HEAD 上的
跑分写下来作为以后的对照线。2026-05-18 18:51 在本机 Hyper-V Linux VM
（Ubuntu 24.04, kernel 6.8.0-111, 8-core）跑通：

| Tier | Case | 耗时 | 备注 |
|------|------|------|------|
| T1 | go-vet | 182ms | clean |
| T1 | go-test | 28.4s | retried（M5/M7 偶发；3 次内通过） |
| T1 | go-test-race | 8.9s | clean |
| T1 | go-bench-smoke | 703ms | clean |
| T1 | 5× const-grep | <1ms each | clean |
| T2 | G1-smoke | 114ms | 30 MiB / 3 迁移 / SHA-256 匹配 |
| T2 | G2-smoke | 30.5s | 30s echo / ~5 迁移 / 0 loss / P99 ceiling met |
| T2 | G3-smoke | 5.5s | 5k pps × 5s QUIC DATAGRAM 4-path bond / 3 ConnID 迁移 / <0.5% loss / P95 < 50ms |
| T2 | G4 | 6.0s | ForceKill path / failover ≤5s |
| T2 | G5 | 325ms | AddPath recover / RecvDups=0 |
| **总** | **14 cases** | **1m20.7s** | **OVERALL: PASS** |

未来在 v0.1.0 HEAD 上跑 phase 1 偏离这条基线 >50%（任一案例时长 / loss /
P95 / migration count）应当触发回归调查。Windows 本地 phase 1 不跑 -race
+ bench-smoke（已 SKIP linux-only），其余应在 45-50s 完成。

`reports/last_phase1.json` 持续记录最新一次绿状态的 commit-sha；phase 2
启动门禁查的就是这个文件。

## v0.3.0 main 回归里程碑（2026-05-22）

commit `4b9e8e5` 已快进到 `main` 并推送到 `origin/main`。该提交在本机
Hyper-V Linux VM 上完成一次完整 `regress --full`，总耗时 `1h44m2.838s`，
结果 `OVERALL: PASS`。

本次里程碑的验收面：

- T1/T2 全绿，包含 `go test ./...`、`go test -race ./...`、bench smoke、
  G1/G2/G3/G4/G5 smoke 和 M11 UDP relay smoke。
- T3 xray matrix 全绿，包含 VLESS/Trojan/VMess/SS2022、REALITY、MLKEM、
  nested、reverse、Glue A migration、stream/packet balancer、packet UDP cases。
- T4 release long-run 全绿：1 GiB TCP、1 GiB QUIC、prime/race/bond 三组
  30 min G2、M11 UDP relay/WireGuard/Hysteria2，以及 5 min `100k pps`
  G3 QUIC DATAGRAM。
- T5 TCP fallback 全绿：privileged `tcprepair`、privileged/unprivileged
  `gvisor`、unprivileged `tcprepair -> gvisor fallback`、以及外部
  `ListenGVisorPacket` packet-carrier。

这标记当前计划内的通用 `net.Conn` / `net.PacketConn` 无损迁移、xray 友好
兼容、M11 自管 UDP 承接、以及 TCP_REPAIR 不可用时的 gVisor fallback
均已达到既定 regression gate。后续若探索 TCP-based stream carrier 到
UDP-based reliable stream carrier 的跨承载迁移，应在此基线之上新增专项
回归，不回退既有金标准。

专项探索已经从该基线继续推进：`TestM2TCPPathDeathFailsOverToUDPBackedStream`
覆盖 TCP path 承载文件传输前半段、TCP path 被强制杀死、同一 rendr `Conn`
继续通过 UDP-backed QUIC stream path 无损完成传输，并校验 SHA-256、迁移计数
和 `FlowID` 不变。

## 灰度门禁

任何 commit 进 main 之前：

1. G1 至少跑一次成功
2. G2 至少跑一次成功
3. G3 必须跑（如果 commit 影响 QUIC 路径）
4. G4 + G5 每次都跑

任何 release tag 之前：

1. G1-G5 全部各跑 ≥3 次，成功率 = 100%
2. 在 ≥2 种网络拓扑（同机、跨主机、跨 VM）上跑
3. 在 ≥1 个真实带宽受限链路上跑（不是纯模拟）

## 不达标处理

**未达到 G1-G5 不能宣告"实现完成"，不能 release，不能合并到 main**。

如果实现路线（M1 双端 / M2 TCP_REPAIR / M3 gvisor）跑不过 G1，必须切到下一条路线，不能"凑合发"。

CLAUDE.md 里的"自主探索直到达成目标"规则在这里具体化：每次迭代尝试一种实现 → 跑 G1-G5 → 失败就分析+换方案 → 再跑。**不允许跳过测试上线**。

## 与 xray 兼容性的关系

xray 集成（见 `docs/xray-integration.md`）必须**在 G1-G5 通过之后**才做。先在独立测试 harness 里跑通金标准，再封装成 xray 兼容接口。

集成完成后，xray 自身的回归测试（vmess/vless/trojan over rendr-transport）也是 release 门禁的一部分，但替代不了 G1-G5。
