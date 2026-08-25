Commit: cf75fa7
# e2e

## 职责
- 全链路 e2e harness（`crates/e2e`，bin `flannel-e2e`）：每个场景在 scratch netns 拓扑里拉起**真实** flanneld（进程内）+ mock kube apiserver（可用 watch），驱动**真实** `flannel` CNI 二进制与真实 bridge/host-local 插件；`cargo test -p e2e` 全量跑，`flannel-e2e --list`/`-- <场景名>` 选择

## 场景
- 12 通过 + 2 环境性 SKIP（ipsec 需 strongSwan charon、tencent-vpc 需真实云 API）：alloc/hostgw/vxlan/ipip/wireguard/udp 数据面（双节点 pod↔pod ping）、extension-hooks、masq(iptables/nftables)、--version、etcd 拒绝、healthz

## 关键设计（踩坑固化）
- **br_netfilter 下网桥包走 FORWARD 链**：宿主 FORWARD policy DROP 会静默丢弃 overlay 外层包（计数器实证），`build_bridge_topology` 必须插 `-I FORWARD -i/-o <br> -j ACCEPT`，Drop 时回收
- **多 daemon e2e 必须注入 per-node `WIREGUARD_KEY_FILE`**：默认共享 `/run/flannel/wgkey` 会导致双节点同公钥握手失败（`DaemonSpec::env`）
- **自愈**：`reclaim_addr` 在建拓扑前回收被 kill 的历史运行残留的固定 IP 链路；每场景前清 host-local IPAM 全局状态
- extension hook 的 stdin 是**第二参数**（`$2`），不是 `$1.stdin`

## 依赖与接口
- 依赖 flannel-core/flanneld（in-process daemon）+ 兄弟二进制 flannel/flanneld；root + CNI_PLUGINS_TGZ（默认下载 cni-plugins）
