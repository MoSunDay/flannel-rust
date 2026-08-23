Commit: af6c3b4
# P7–P7b：drop-in e2e、README + 仓库记忆、顶层 LICENSE

## 变更内容
- P7（8bd60f9）：drop-in e2e `crates/flannel/tests/dropin_e2e/` — mock apiserver +
  flanneld::run（alloc 后端）写 subnet.env；flannel 二进制（CARGO_BIN_EXE）在新建
  netns 中用真实 bridge/host-local 插件执行 CNI ADD；断言 pod IP 落在租得 /24 内；
  DEL 幂等 + 守护进程干净退出（main.rs 369 行 + mock_apiserver.rs 176 行）
- P7a（b839606）：顶层 README.md + 仓库本地记忆（agents.md、
  agents/{flannel-core,flanneld,flannel-cni}/index.md、features/index.md、本 changelog）
- P7b（af6c3b4）：顶层 `LICENSE` — Apache-2.0 规范全文 202 行，逐字复制自上游
  flannel（sha256 cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30），
  与 Cargo.toml:13 `license = "Apache-2.0"` 对齐

## 验证
- `cargo test --workspace` → 340 passed / 0 failed / 1 ignored
  （含 `dropin_daemon_subnet_env_cni_pod_veth` 具名通过），退出码 0
- `cargo clippy --workspace --all-targets -- -D warnings` → 零警告；
  `cargo build --workspace` 与 `cargo build --release --offline` 均退出码 0
- 行数约束：dropin_e2e/main.rs 369 ≤ 400、mock_apiserver.rs 176 ≤ 400、LICENSE 202 ≤ 400
- 提交序列：2f979c2（P6）→ b839606（P7a）→ 8bd60f9（P7）→ af6c3b4（P7b）
