# chaos harness 待办

## 短期

- [x] g1 binary 雏形（任意 size + N migrations + SHA-256）
- [ ] g1 baseline 模式：跑无迁移基线，记录 throughput；比较时只看 ±10% 退化
- [ ] g2 binary：echo 长驻 + 随机迁移；接 `-duration 30m`
- [ ] chaos 编排器（`cmd/chaos/main.go`）按 `schedule.yaml` 跑 G1-G5 序列
- [ ] tc netem / 限速集成（前置：要在 Linux 上跑）

## 关键决策点

- `rendrInternal` / `engineHook` 接口：chaos binary 跨模块拿不到 `internal/engine`。
  当前用接口断言绕过；之后视情况把 `Migrate` 提升到 `rendr.Conn` 的（test/admin-only）
  扩展接口里，或加一个 `rendr/admin` 子包。

## 不在 chaos 里的

- 应用层协议（vmess / SOCKS5 / 自定义）— 那是 M9 / M10
- 跨主机拓扑（demo VM / JPB / AUB）— 由 `docs/test-hosts.md` 列出的脚本驱动
- 性能基线 baseline.json — release-gate 子任务，待 M2 后做
