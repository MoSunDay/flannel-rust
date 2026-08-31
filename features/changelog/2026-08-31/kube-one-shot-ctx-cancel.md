# kube 客户端一次性请求接入 ctx 取消（对齐 Go client-go），修 e2e healthz 间歇挂死

## 症状
- e2e `healthz-readyz` 全量 harness 下 ~50% 失败：daemon 卡在 `complete_lease` 的 /status PATCH，15s `shutdown()` 窗口耗尽（孤立复现 0.6s 通过；masq daemon patch ~1.2ms）。
- 实证链：PATCH 的 TCP 握手被黑洞（服务端未见请求、无 host 侧 ESTAB），客户端卡满 30s `connect_timeout`——`complete_lease` 传给 `patch_node_status` 的是被忽略的 `_ctx`。

## 修复（Go parity）
- Go `CompleteLease`（kube.go:639）把 ctx 传入 `PatchStatus`，client-go 取消在途请求；daemon 经 `wg.Wait()`（main.go:509-513）等它退出。Rust 侧此前在途请求不可取消，等价于把 30s 拨号超时抬进关停路径。
- `kube/client.rs`：`KubeError::Canceled`；get_pod/get_node/list_nodes/patch_node/patch_node_status/patch_node_at 及内部 `request_json` 首参 `&CancellationToken`，send+read 整轮 `tokio::select!` 竞速 `cancel.cancelled()`。watch 流式路径（`watch_nodes`）本已取消感知，不动。
- 调用点换 `ctx`：acquire（fetch_node、patch_with_retry）、informer list、status `complete_lease`、watch_ops 存储 MAC/IP 读取；`resolve_node_name` 用分离 token（Go 构造器 context.TODO parity）。
- 错误映射无需改动：`complete_lease_exit_code`（flanneld daemon.rs）对任意 Err 记日志 + exit 0，与 Go 关停输出一致。

## 回归钉死
- 客户端级：accept-不响应黑洞服务器上在途请求，cancel 后 <5s 返回 `KubeError::Canceled`（`kube/tests.rs`）。
- 管理器级：绕过 informer 同步直建 manager，`complete_lease` PATCH 中途 cancel <5s 返回 canceled（`kube_integration_tests.rs`，即 flake 模式）；变异检查（换回不取消 token）证实用例挂死不通过。

## 验证
| 项 | 结果 |
|----|------|
| fmt / clippy `-D warnings` | 0 警告 |
| `cargo test --workspace` | 全绿（flannel-core 330 passed） |
| e2e 全量 | 12 PASS / 2 环境性 SKIP |
| `healthz-readyz` 连跑 + 16 线程负载下 3 连跑 | 全过 |
