# 可调用测试主机

均通过默认 SSH key 连接（除明示需要密码的 iKuai）。**Linux 默认登录用户为 root**。所有破坏性实验前先确认快照可用性。

## 内网测试集群（10.130.32.0/24）

### `root@10.130.32.32` — demo VM

- 用途：通用 demo 容器宿主机
- 网络：与 `10.130.32.0/24` 同段，无 NAT
- 性能：可承载多容器并发，限速测试推荐宿主
- 状态：长驻可用，可恢复

### `root@10.130.32.20` — "node20"

- 用途：本地 production-shape 节点（hy2scale 历史用途）
- 自 2026-05-10 起从 Windows Desktop 迁出
- rendr 项目下作为"另一端的 rendr 实例" 候选

### iKuai v3 `10.130.32.40`

- 登录：用户 `sshd`，密码 `test1234`
- 用途：路由器形态客户端
- VPN 设置稳定，是 IKEv2/L2TP 长期验证机
- rendr 适用：作为"路径上的中间盒"测 conntrack / NAT 表项老化

### iKuai v4 `10.130.32.41`

- 登录：用户名密码同上 (`sshd` / `test1234`)
- 用途：iKuai v4 新版兼容性测试

## DNS 污染 / GFW 模拟主机

### `root@172.20.0.107`

- 长驻 Ubuntu VM
- **真实 DNS 污染 ISP 环境**——内置 GFW 风格 DNS 注入
- 同时可达 `10.130.32.0/24`（172.20.0.0/16 ↔ 10.130.32.0/24 内网直通）
- 快照可恢复，破坏性实验 OK
- rendr 适用：验证路径"看似活但实际被劣化"的边界情况、DNS-driven 路径选择

## 海外节点

### `aub.tular.io` — "AUB"

- 区域：澳洲
- 容器模式：host network
- L2TP 已配 `--device-cgroup-rule="c 108:0 rwm"`（保留）
- rendr 适用：跨地域长 RTT 路径测试

### `root@176.97.73.24` — "JPB"

- 区域：日本
- bridge 网络，标准 docker 部署
- rendr 适用：第二条跨地域路径，与 AUB 配合做"多出口冗余"

## 本地 Windows 工作站

- `D:\hy2scale` 是历史项目
- `D:\rendr` 是当前项目工作目录
- 不作为测试节点（Windows ≠ rendr 主目标平台，仅做编辑 + git）

## 连接方法速查

```powershell
# 默认 key 登录（PowerShell）
ssh root@10.130.32.32
ssh root@10.130.32.20
ssh root@172.20.0.107
ssh root@176.97.73.24
ssh root@aub.tular.io

# iKuai（密码登录）
ssh sshd@10.130.32.40
# password: test1234

# 复制文件
scp ./binary root@10.130.32.32:/root/
```

## VM 内启动容器（形态 A）

测试拓扑通常在 `10.130.32.32` 上拉起：

```bash
ssh root@10.130.32.32
cd /root/rendr-test  # 测试拓扑 compose
docker compose -f compose.rendr.yml up -d
```

测试拓扑文件 **不进** rendr 仓库（test/ gitignored），按需现写。每个 milestone 的固化拓扑可考虑放到 `D:\rendr\test\` 下作为本地参考。

## 真实带宽限速准备

需要带宽限速的测试在容器层加 tc：

```bash
# 容器内 50 Mbps 限速（在容器命名空间内执行）
tc qdisc add dev eth0 root tbf rate 50mbit burst 32kbit latency 400ms
```

或在 docker network 层（用 macvlan + qdisc 组合，参考 `docs/testing.md`）。

## 路径质量模拟

`tc netem` 在容器内：

```bash
# 30ms 延迟 + 5ms 抖动 + 1% 丢包
tc qdisc add dev eth0 root netem delay 30ms 5ms loss 1%

# 移除
tc qdisc del dev eth0 root
```

## 不要做的事

- 不在 iKuai 主路由器上跑破坏性实验（影响内网其他设备）
- 不在 AUB / JPB / 10.130.32.20 上跑可能挂掉服务的实验（这些机器对 hy2scale 仍是生产角色）
- 不在 172.20.0.107 上**长期**占用大量流量（共享 ISP 出口）

破坏性实验首选 `10.130.32.32` 内的临时容器或临时拉一台新 VM。
