Commit: 2f979c2
# 业务能力索引

## 能力清单
- **flanneld 覆盖网络管理**：9 后端（alloc 默认/host-gw/ipip/vxlan/wireguard/udp/extension/ipsec/tencent-vpc），kube-subnet-manager 模式，lease 注解与 acquire 重试，subnet.env 输出，iptables/nftables masq
- **CNI 接入**：`flannel` 元插件读 subnet.env，委托 bridge+host-local，可选 masq 链
- **兼容性目标**：与 Go flannel@cdf76059 flag/文件/注解/协议字节级对齐（subnet.env、annotation JSON、CNI 配置）

## 变更记录
- [changelog/](changelog/)（按日期目录）
