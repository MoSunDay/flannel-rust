Commit: (working-tree)
# netlink spike 示例拆分：414 行单文件 → 三文件各 ≤200

## 背景
- 上线标准复核发现 `crates/flannel-core/examples/netlink_spike.rs`（P0 遗留）
  414 行，是全仓唯一超过「新增文件 ≤400 行」约束的文件，予以纠正。

## 变更
### 拆分为目录式多文件 example（代码逐字节搬迁，零逻辑改动）
- **`crates/flannel-core/examples/netlink_spike/main.rs`**（124 行）：常量 +
  共享格式化助手（mac_str/neigh_addr_str/rterr）+ main/run_async
- **`crates/flannel-core/examples/netlink_spike/read.rs`**（120 行）：只读
  survey（link/address/route dump、fmt_route）
- **`crates/flannel-core/examples/netlink_spike/write.rs`**（200 行）：
  NET_ADMIN 门控的变更操作（vxlan/addr/ARP/FDB/route）+ list_back + 清理
- 删除原 `crates/flannel-core/examples/netlink_spike.rs`

## 测试覆盖
| 功能 | 验证方式 | 结果 |
|------|----------|------|
| 行为等价 | `cargo run -p flannel-core --example netlink_spike` | SPIKE OK（netns 内完整 rtnetlink 往返），退出码 0 |

- 全量回归：`cargo test --workspace` → 340 passed / 0 failed / 1 ignored
- clippy：`cargo clippy --workspace --all-targets -- -D warnings` → 零警告
- 行数：124 / 120 / 200 ≤ 400

## Impact Surface
- 仅 examples/ 开发 spike；不影响 flanneld/flannel 二进制与任何库代码。
