# flannel-rust

Rust rewrite of [flannel](https://github.com/flannel-io/flannel) (upstream
baseline `cdf76059`): a drop-in `flanneld` network daemon and `flannel` CNI
meta-plugin for Kubernetes, targeting kube-subnet-manager deployments
(k3s-style init-pro HTTP apiserver). Apache-2.0.

## Crates

| crate | bin | purpose |
|---|---|---|
| `flannel-core` | — | ip/lease/subnet primitives, kube client, subnet managers, all 9 backends, traffic managers |
| `flanneld` | `flanneld` | daemon: flags (Go-compatible), subnet lifecycle, healthz, systemd notify |
| `flannel-cni` | — | CNI meta-plugin library (subnet.env → bridge+host-local delegation + masq) |
| `flannel` | `flannel` | CNI plugin binary (ADD/DEL/CHECK/VERSION exec protocol) |

## Backends

`alloc`, `host-gw`, `ipip`, `vxlan` (default), `wireguard`, `udp`,
`extension`, `ipsec` (strongSwan via hand-rolled VICI + raw xfrm netlink),
`tencent-vpc` (TC3-HMAC-SHA256 VPC API v3).

## Highlights

- Pure-functional style: plain structs + free functions, traits only for
  backend/manager polymorphism (`BoxFuture` + `CancellationToken` ctx).
- Netlink via `rtnetlink`/`netlink-packet-route`; generic netlink wgctrl,
  VICI and xfrm protocols implemented by hand (offline build constraint).
- Traffic managers: iptables and nftables masquerade/forward rules.
- Tests include live-kernel integration (wireguard/xfrm/tun/netns/iptables)
  and a mock-apiserver e2e daemon test.

## Build & test

```sh
cargo build --workspace --release
cargo test --workspace
```

Linux-only; integration tests require root with CAP_NET_ADMIN/CAP_SYS_ADMIN.

Run the daemon against a kube-subnet-manager apiserver:

```sh
flanneld --kube-subnet-manager --kube-api-url=http://127.0.0.1:10250 \
  --kubeconfig-file=/path/kubeconfig --iface=eth0
```
