Commit: 2f979c2
# Pre-release bug sweep：5×P0 功能缺陷 + 5×P1 安全/对齐项

## 背景
- 发布前系统排查，与 Go 上游（cdf76059）逐项比对；每项均以回归测试钉住。

## 变更
### P0 功能缺陷
1. **Node 注解写 /status 子资源**：`patch_node_status`（`kube/client.rs`），CompleteLease/EnableIPV6 等 status 变更走 `/status`；主资源 patch 断言为空
2. **subnetfile 解析掩码宿主位**：`parse_ip4net`/`parse_ip6net` 走 `.network()`（Go `net.ParseCIDR` 同语义），`10.244.1.1/24 → 10.244.1.0/24`
3. **EventHub 背压失效**：`publish` 改 async——锁内快照 senders、锁外 `send().await`，Closed 接收者按 `same_channel` 退役；慢消费者阻塞上游（Go `chan<-` 语义）
4. **lease 事件信号量不阻塞**：`enqueue_lease_event`/Add/Update handler 改 async，`select!{ cancelled(), acquire_owned() }`（Go `Acquire(ctx,1)` 阻塞语义），informer 全链路 await
5. **ipip MTU 对齐偏差——计划撤销**：核实 Go `oldMTU > expectMTU || oldMTU == 0` 即**只降不升**，Rust 原实现已一致；提取 `should_apply_mtu` 纯函数 + 钉住 jumbo/no-raise、运维缩 MTU/no-fixup 两场景。⚠ 原计划"恒设 expectMTU"系对上游误读，未采纳

### P1 安全/对齐
6. `addr_ip` 优先 IFA_LOCAL、IFA_ADDRESS 兜底（Go `addrIP` 同序）
7. wireguard 私钥单步 `OpenOptions::mode(0o400)` 创建（消除 0600→0400 窗口）
8. acquire 三处 bail 文案拆分：轮询超时 "failed to get node" / patch 重试 "failed to patch node"
9. `Interrupted` 类型化错误（`subnet/mod.rs`），daemon 按 `is::<Interrupted>()` 判定
10. extension.rs fmt 修正

## 测试覆盖
| 项 | 结果 |
|----|------|
| `cargo fmt --all -- --check` / clippy `-D warnings` | 0 警告 |
| `cargo test --workspace` | 全绿（flannel-core 297 + hub/sentinel 回归、e2e harness 12 passed / 2 环境性 SKIP） |
| `cargo test -p flannel-core ipmatch -- --ignored` | 1 passed |
| `cargo build --release` | ok |
| 行数约束 | 新文件最大 85（hub_tests.rs）；迭代文件最大 428 ≤ 800 |
