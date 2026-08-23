Commit: 2f979c2
# flannel Rust 移植完成（P0–P6）

## 变更内容
- P0：workspace 脚手架；ip/lease/mac/utils/flags/subnet.config/writefile/netlink spike
- P1：kube 客户端、subnet Manager trait、kube subnet 管理器（mock apiserver 测试）、flanneld 守护进程 + e2e
- P2：route_network + host-gw/ipip/vxlan 后端
- P3：trafficmngr（iptables + nftables，含活体内核生命周期测试）
- P4：wireguard（手写 genl wgctrl + curve25519 密钥）、udp（tun + 代理）、extension
- P5：ipsec（手写 VICI + xfrm netlink）、tencent-vpc（TC3-HMAC-SHA256 签名）；9 后端全部注册
- P6：flannel CNI 元插件（真实 bridge/host-local netns e2e）

## 验证
- 全 workspace 339+ 测试 × 连续 3 轮全绿；release 构建通过；含活体内核集成测试
- 提交序列：a48d31f … 2f979c2（每阶段一个提交）
