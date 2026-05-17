# 模式：prime / bond / race

## 模型

每条 rendr `Conn` 在创建时绑定一个 Mode。所有三种模式共用：
- flow_id（连接生命周期内不变）
- SEQ（全局单调）
- bridge 状态机（active / suspended / dead）
- 90s 迁移预算
- cleanClose 鉴别

差别在 **scheduler.Submit(frame) → []PathConn** 与 **scheduler.OnRecv(frame, ...)** 的实现。

## prime

**目标**：在所有可用路径中，把流量定在最稳定的那一条上；当它退化时迁移到次优。

**Submit**：返回**当前主路径**，一条。

**OnRecv**：单路径流，直接交付。

**迁移决策**（外部观测，不看自身流量）：
- 每条路径独立探测 rtt / jitter / loss
- 综合分 `score = rtt_p50 + α·jitter + β·loss_pp`
- 当 `score(primary) > score(best_other) × (1 + hysteresis)` 持续 `dwell` 秒，触发迁移
- 迁移完成后 `cooldown` 秒内不再做迁移决策（避免抖动）

**推荐默认**：hysteresis=0.25, dwell=5s, cooldown=30s

**失败语义**：
- 主路径死 → 90s 内有任何路径活就立即迁过去（不等 dwell）
- 所有路径死 → 进 suspended，等任意路径恢复或预算耗尽

**适用**：SSH、RDP、控制信道、对低抖动敏感的应用

## race

**目标**：每帧并行发到所有可用路径，先到先用、后到丢弃。

**Submit**：返回**所有 active 路径**。

**OnRecv**：按 SEQ 维护一个 dedup 窗口（建议 4096 槽），看到首次到达就交付，已见过的丢弃。

**带宽特性**：N 条路径 = N 倍带宽消耗，但传输有效吞吐 ≈ 单路径吞吐（race 是冗余而非聚合）。

**失败语义**：
- 任意路径活 → 用户连接活
- 全部路径死 → 进 suspended
- 路径死亡几乎不影响用户（其他路径已经提前送过同一帧）

**适用**：金融交易、游戏控制流、强稳定性 < 10s 应用层超时的协议

**注意**：
- 不适合大文件传输（带宽放大不可接受）
- 上行需要回程 ACK / SACK 时，回程也要 race，否则瓶颈在 ACK
- dedup 窗口溢出 = bug（必须有溢出检测和告警）

## bond

**目标**：多路径帧级聚合，单连接吞吐叠加到所有路径之和。

**Submit**：根据每条路径的拥塞窗口估计、queue 长度，**把当前帧分配到一条路径**（不是分片，是整帧）。带宽 = Σ 各路径瓶颈。

**OnRecv**：按 SEQ 重排，恢复发送序。

**核心子问题**（hy2scale bond.go 全部踩过）：

1. **path pinning**：连续若干帧绑定到同一 path，避免 reorder 暴涨
2. **stuck path 检测**：5s read deadline + write timeout；不能用"长时间没数据"误判
3. **reorder window 自适应**：基于路径间 RTT 差异动态调整
4. **teardown 双向通知**：路径关闭时上游和下游各自发 teardown 帧，去重靠 SEQ
5. **redistribute on death**：死路径上"已提交但未送达"的帧，重发到活路径
6. **reopen 跳过 torn-down path**：teardown 完成的路径短时间内不重连

**失败语义**：
- 任一路径死 → 该路径上未确认的帧通过其他路径 redistribute；用户感知短暂带宽下降
- 死路径恢复 → 自动重新加入聚合
- 所有路径死 → 进 suspended

**适用**：大文件传输、视频流、需要叠加多家运营商带宽的家用场景

**警告**：bond 是 M8，放最后做。**先把 prime + race 稳到混沌测试 10/10 PASS 再碰**。

## 切换规则

- prime ↔ race：随时可切（两边都基于"完整帧到达 = 完成"语义）
- prime / race → bond：可切，但切完前需要让 OnRecv 的 reorder buffer 初始化
- bond → prime / race：可切，但要先 drain bond 的 reorder buffer

切换由控制帧 `MIGRATE_NOTIFY` 携带，双端 ACK 后切换生效。单端切换非法。

## 配置示例

```go
dialer := rendr.Dialer{
    Mode: rendr.ModePrime,
    Paths: []rendr.PathSpec{
        {Transport: "tcp",  Endpoint: "1.2.3.4:443"},
        {Transport: "tcp",  Endpoint: "5.6.7.8:443"},
        {Transport: "quic", Endpoint: "1.2.3.4:443"},
    },
    Hysteresis: 0.25,
    Dwell:      5 * time.Second,
    Cooldown:   30 * time.Second,
}
conn, err := dialer.Dial(ctx, "tcp", "target:80")
```
