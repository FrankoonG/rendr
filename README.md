# rendr

连接（tcp和udp）无损迁移框架，独立项目

prime：稳定性优先！选取多路径中延迟和抖动最小的路径。xray-core具有类似算法（BalancerObject）
bond：速度优先！多路径聚合带宽叠加，单连接高吞吐。
race：不惜一切代价稳定！同时多路径发包到目的，先到哪个包用哪个。

核心在于tcp与tcp，以及udp（quic）与udp之间进行无损连接迁移，可以不强求tcp和udp之间无损迁移
其中tcp无损迁移难点在于可能需要先研究TCP_REPAIR/CRIU在linux下的实现方案，fallback方案可以是gvisor内实现tcp无损迁移