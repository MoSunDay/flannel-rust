Commit: cf75fa7
# P8：全链路 e2e harness 落地，套件转绿（12 passed / 0 failed / 2 skipped）

## 背景
- 上一会话中断于 extension-hooks 场景失败（stdin 断言超时）；本轮完成根因定位、全套件修复与转绿。

## 变更
### P8a：flannel-cni 行为对齐上游
- bridge 委托默认 `isGateway=true`（用户显式提供时保留）；netconf 单测覆盖默认/覆盖两条路径
- 库级 e2e（`crates/flannel-cni/tests/e2e.rs`）整条 CNI 链改在 scratch netns 内执行，bridge 落在该 netns、随其销毁，不再触碰真实宿主

### P8b：drop-in e2e 隔离
- `crates/flannel/tests/dropin_e2e/main.rs`：CNI 子进程在 scratch host netns 内执行（bridge 插件在**调用者** ns 建 cni0），避开宿主已有 cni0（如 k3s 下）

### P8c：新增 `crates/e2e` 全链路 harness（bin `flannel-e2e`）
- 四项根因修复（检索价值点，详见 [agents/e2e/index.md](../../../agents/e2e/index.md)）：
  1. **overlay 网桥 FORWARD ACCEPT**：br_netfilter 使网桥包过宿主 FORWARD 链，policy DROP 静默丢外层包（vxlan/ipip/udp 三场景同根因，iptables 计数器 +3/3 实证）——拓扑构建插 ACCEPT、Drop 回收
  2. **per-node `WIREGUARD_KEY_FILE`**：双 daemon 共享 `/run/flannel/wgkey` → 同公钥握手失败；`DaemonSpec::env` 注入
  3. **extension-hooks stdin**：hook 的 stdin 是第二参数（`$2`），非 `$1.stdin`
  4. **`reclaim_addr` 自愈**：建拓扑前回收被 kill 运行残留的固定 IP 链路（`ip -o addr` 解析注意 ifindex≠接口名）

## 测试覆盖
| 项 | 验证 | 结果 |
|----|------|------|
| e2e 全量 | `target/debug/flannel-e2e` | 12 passed / 0 failed / 2 skipped（ipsec/tencent-vpc 环境性 SKIP，附理由），exit 0 |
| 工作区单测 | `cargo test --workspace --exclude e2e` | 全部 ok（292/25/8/5/3/2×3/1×2/0×5），0 failed |
| drop-in e2e | `cargo test -p flannel --test dropin_e2e` | 1 passed |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | 零警告 |
| 行数约束 | `wc -l` | 新增文件最大 386 ≤ 400 |
| 宿主残留 | netns / e2e 链路 / iptables 规则 / 10.99.x 地址 | 全部 0（自愈闭环） |

## Impact Surface
- 新增 `crates/e2e`（纯测试 harness，不入产物）；flannel-cni delegate 行为向 upstream 对齐（isGateway）；drop-in/库 e2e 仅测试代码变化，二进制逻辑不变。
