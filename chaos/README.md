# rendr chaos harness

独立的 Go 子模块，承载 G1-G5 production-scale 测试以及 chaos schedule（多路径混沌扰动）。

**不在主包里**的理由（CLAUDE.md / docs/architecture.md）：
- 主包 `go test ./...` 要能在几秒钟内跑完
- 这里的测试动辄数 GB / 30+ 分钟，CI 不一定每次跑
- 依赖 root / CAP_NET_ADMIN / docker / tc netem 的拓扑模拟会污染主包构建

## 现状

| binary | 状态 |
|--------|------|
| `cmd/g1` | 雏形落地：N GiB 流 + 多次规划迁移 + SHA-256 |
| `cmd/g2` | 雏形落地：echo 长驻 + 随机迁移 |
| `cmd/g3` | 待办 (M2 之后) — 100k pps QUIC |
| `cmd/g4` | 待办 — path 强杀 + 备份恢复 |
| `cmd/g5` | 待办 — path 回归判定 |
| `cmd/chaos` | 待办 — 编排器：跑 schedule.yaml 中的 chaos 序列 |

每个 binary 用 `--report=path/to/file.json` 写结构化结果，便于 CI 解析。

## 跑法

```
cd chaos
go run ./cmd/g1 -size 1GiB -migrations 3 -report g1.json
go run ./cmd/g2 -duration 30m -migrations 30 -report g2.json
```

## 验收门禁

`docs/success-criteria.md` 的 G1-G5 是判定"实现完成"的唯一标准。
每个 binary 内置判据：跑完后 exit code = 0 表示通过，非零表示退化或失败。
CI 用 exit code 决定 release gate。

## 与主包的耦合

主包 `go test ./...` 跑的是 G1/G2 **雏形**（数十 MB / 数秒），证明 API +
引擎不变量。chaos harness 跑的是金标准全量，证明 release-readiness。
两层都通过才能 release。
