Commit: 2f979c2
# flannel-rust 仓库逻辑地图

flannel（Go 上游 `cdf76059`）的 Rust 重写：`flanneld` 守护进程 + `flannel` CNI 元插件，
仅支持 kube-subnet-manager（k3s/init-pro HTTP apiserver），Linux-only，Apache-2.0。

## 模块索引
- [flannel-core](agents/flannel-core/index.md)：ip/lease/subnet 基础类型、kube 客户端、subnet 管理器、9 个后端、流量管理器
- [flanneld](agents/flanneld/index.md)：守护进程（Go main.go 移植，flags/healthz/systemd/subnet 生命周期）
- [flannel-cni](agents/flannel-cni/index.md)：CNI 元插件库（subnet.env → bridge+host-local 委托）
- [e2e](agents/e2e/index.md)：全链路 e2e harness（真实 flanneld + CNI，netns 拓扑，12 场景）

业务能力与变更记录见 [features/index.md](features/index.md)。
