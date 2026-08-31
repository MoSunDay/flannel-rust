# Production-readiness bug sweep #2：3 项实证缺陷修复 + 3 项误报钉死 + 嵌入路径闭环

## 背景
- 目标：扫除 bugs、确认可承载线上流量（全部 9 后端，harness + 真实 k3s staging 验证）。
- 方法：3 路只读审计 → 每项结论先对 vendored 上游（`link_repos/flannel`，恰为 cdf76059）核实再动手；vendor 源码为权威，推翻了两条来自"记忆中上游"的误报。

## 实证缺陷修复
1. **4 后端 run loop 关闭挂死/僵尸**（vxlan/wireguard/extension/ipsec）：pinned watch future 持有 mpsc Sender 不释放 → 关闭时挂死至 SIGKILL（无规则清理）或 watch 出错后僵尸持 lease。改为 `tokio::spawn` 任务持有 sender（route_network 模式），channel 关闭即返回；`subnet/watch.rs` 会话级重试（1s→30s，ctx 竞速）对齐 Go `subnet.WatchLeases`。vxlan：Netlink 单次创建（失败 fatal）、锁中毒 `into_inner`、`retry_do` 退避接入 cancel。
2. **CNI `delegate.ipam.routes` 被静默覆盖**：guard 改为 delegate 顶层与 `ipam.routes` 双位置判断；文档契约同步。
3. **CNI `exec_delegate` 管道写满死锁**：stdin 改 writer 线程并发写 + `wait_with_output()` 排空；回归测试证明旧实现 exit 124 挂死。
4. **DEL 幂等**：subnet.env 存在但缺关键字段 → 与缺失同路径 `minimal_delegate_conf` exit 0（ADD/CHECK 仍严格）。
5. **kube 客户端 30s connect_timeout**（不设全局 timeout，watch 长轮询保持无界）。
6. **panic/资源面**：genl 短 NLMSG_ERROR `error_code_of` 安全切片；`parse_family_ops` 消除 `m[4..]` 切片 panic；VICI 帧长 64KiB 上限（防 charon OOM）；xfrm 短消息 warn + 连续 8 次有界 bail。
7. **flanneld**：healthz-port `u16::try_from`（70000 不再静默变 4464）；`Options::default()` 委托 flag registry 单一事实源；类型化 `Canceled` 哨兵替代字符串匹配。
8. **存储 MAC 注解键**（`watch_ops.rs`）：改用规范化键（`annotations.backend_data`），修复自定义 `--kube-annotation-prefix` 下 MAC 复用失效。**记录为对上游的有意偏离**：vendored kube.go:711/719 同样用原始前缀（上游潜在 bug），Go 的 `GetStoredPublicIP` 则用规范化键。

## 误报钉死（vendor 权威）
- **lease 事件变更检测**：Go kube.go:318 `var changed = true` + 双 family AND 清除，与 Rust 逐字一致——双栈单 family 变更不发事件是**上游同款行为**，非移植 bug；7 个 parity 钉死测试防漂移。
- **CompleteLease 失败退出码**：Go main.go:500-513 仅记日志（Interrupted 才 cancel）后 `os.Exit(0)`——Rust exit 0 即 parity；Interrupted 唯一产出方是 etcd local_manager（kube 模式不可达，保留以对齐 Go 文本）。3 单测 + 1 e2e 注入 500 钉死。
- **wireguard genl 能力位**：安装的 uapi 头（`DO=0x02/DUMP=0x04/HASPOL=0x08`，0x01 是 ADMIN_PERM）+ 真内核 CTRL_GETFAMILY 探测（op0 flags 0x1c、op1 flags 0x1a）证明**原常量正确**；落地的是 panic 修复、get≠set 哨兵回退与 10 个 uapi 位钉死测试（含真内核用例）。

## 嵌入路径闭环（init-pro）
- `Options::install_signal_handlers`（工作区既有 WIP，本轮完成）：`run()` 包装 `run_inner()`，**所有**退出路径 cancel + drain 任务；信号流同步注册、安装失败走启动 Err（exit 1），不再 task 内 `.expect`；嵌入方经 CancellationToken 驱动关闭，默认 true 与 Go 一致。

## 测试覆盖（全绿）
| 项 | 结果 |
|----|------|
| fmt / clippy `-D warnings` | 0 警告 |
| `cargo test --workspace --exclude e2e` | 397 passed / 0 failed |
| `cargo test -p e2e` | 12 PASS / 2 环境性 SKIP（ipsec 需 charon、tencent-vpc 需云 API） |
| `cargo build --release` | ok |
| 真内核 wireguard genl 用例 | configure_get_lifecycle 等 17 项通过 |
| 行数约束 | 新文件最大 228 ≤400；迭代文件最大 576 ≤800 |

## 遗留
- 真实 k3s staging 验证为本机外 gating item（本机无 k3s/kubectl）：2 节点逐后端 pod↔pod、apiserver 重启、SIGTERM 清理时延、lease 续租观察；ipsec/tencent-vpc 需环境前置。
