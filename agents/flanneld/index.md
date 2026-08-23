Commit: 2f979c2
# flanneld

## 职责
- 守护进程入口（Go main.go 移植）：flags（Go 风格，`flags_defs.rs`）、subnet 生命周期（`subnet_mgr.rs`+`daemon.rs`）、subnet.env 写入（复用 core writefile）、healthz、systemd notify、iface 选择、流量管理器装配

## 边界
- 负责：进程编排、参数、信号与健康检查
- 不负责：后端实现与 kube 协议（在 flannel-core）

## 核心链路
1. 解析 flags → 选 iface → 构造 kube subnet manager
2. acquire lease → 启动 backend（registry 按 `--backend-type` 取）
3. 写 subnet.env → 装配 trafficmngr（iptables/nftables）→ watch lease 变更 → healthz 循环

## 依赖与接口
- 依赖 flannel-core；bin `flanneld`；e2e 测试用 mock apiserver 验证全链路
