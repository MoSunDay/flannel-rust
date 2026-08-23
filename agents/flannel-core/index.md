Commit: 2f979c2
# flannel-core

## 职责
- 网络原语：`ip/`（IP4Net/IP6Net 算术、iface netlink、tun）、`lease/`（租约、MAC）、`mac.rs`、`utils.rs`、`endian.rs`
- kube 客户端（`kube/`）：精简 HTTP apiserver 客户端，仅服务 kube-subnet-manager
- subnet 层（`subnet/`）：`Manager` trait、`config` 解析、`writefile`（subnet.env）、`kube/` 管理器（informer/annotations/acquire/watch）
- 后端（`backend/`）：`traits.rs`（Backend/Network，BoxFuture + CancellationToken ctx）、`manager.rs` 生命周期、`mod.rs` 注册表（9 个后端）、`route_network/` 共享路由缓存
- 流量管理器（`trafficmngr/`）：iptables / nftables masq+forward 规则

## 边界
- 负责：类型、协议实现、后端数据面、规则管理
- 不负责：进程入口/flag 解析（在 flanneld）、CNI 协议（在 flannel-cni）

## 关键设计
- 纯函数风格：struct + free fn；trait 仅用于后端/管理器多态
- 离线约束：generic netlink wgctrl、VICI、xfrm netlink 均手写（无第三方 crate）
- 内核 6.8.0-58 的 wireguard genl cmd id 为 0/1（主线 1/2），动态解析并回退

## 依赖与接口
- rtnetlink 0.23 / netlink-packet-route 0.33 / netns-rs / tokio / kube 相关仅 HTTP
- 对外：`subnet::Manager`、`backend::registry`、`trafficmngr::TrafficManager`
