Commit: 2f979c2
# flannel-cni

## 职责
- flannel CNI 元插件（等价 flannel-io/cni-plugin）：`netconf.rs`（netconf + subnet.env 解析、delegate 配置构造）、`delegate.rs`（CNI_PATH 查找 + exec 委托）、`masq.rs`（FLANNEL-POSTRTG-CHAIN-01 规则）、`skel.rs`（CNI 协议）；bin 在 crates/flannel

## 关键设计
- 强制字段：delegate `ipMasq=false`、`mtu`=FLANNEL_MTU；cniVersion≥0.3.0 用 host-local `ranges`，否则平铺 `subnet`；bridge 委托默认 `isGateway=true`（用户显式值保留，upstream 对齐）
- DEL 幂等：subnet.env 缺失时用 `minimal_delegate_conf`，delegate 错误降级为成功
- 错误输出 CNI error JSON（code 1/4/100）

## 依赖与接口
- 依赖 flannel-core（IP4Net/IP6Net）；输入 CNI_* 环境变量 + stdin netconf；输出 delegate 结果 JSON
