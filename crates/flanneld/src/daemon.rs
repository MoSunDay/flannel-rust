//! The daemon orchestration: port of flannel `main.go` `main()` plus
//! `shutdownHandler` (upstream cdf76059), in Go's exact step order and
//! with Go's log messages.
//!
//! One deliberate deviation for embedders (e.g. init-pro, which installs
//! its own SIGINT/SIGTERM handlers via `tokio::signal` and drives the
//! cancellation token): `Options::install_signal_handlers == false`
//! skips the handler installation entirely (no task spawned, no log);
//! the embedder cancels the token instead. The default (`true`) is
//! exactly Go's behavior.
//!
//! Second invariant: `run` cancels the token and drains every spawned
//! task on EVERY exit path (Go achieves the same with `cancel();
//! wg.Wait()` before each `os.Exit`), so an embedder's shared runtime
//! never inherits leaked tasks from a failed startup.

use crate::healthz::{new_ready_flag, spawn_healthz};
use crate::{iface_select, subnet_mgr, subnetfile, systemd, traffic, Options, VERSION};
use flannel_core::backend::{default_registry, BackendManager, Network};
use flannel_core::ip::iface::{add_blackhole_v4_route, add_blackhole_v6_route, Netlink};
use flannel_core::ipmatch::get_ip_family;
use flannel_core::subnet::Manager;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Whether this run owns SIGINT/SIGTERM: Go always does (the Go-parity
/// default is `true`); an embedder sets
/// `Options::install_signal_handlers = false` and drives the
/// `CancellationToken` from its own signal handlers instead.
fn owns_shutdown_handler(opts: &Options) -> bool {
    opts.install_signal_handlers
}

/// Go main.go:265-268: the "Installing signal handlers" log plus
/// `signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)`, then the
/// `shutdownHandler` goroutine (main.go:277-281). Port deviation for
/// embedders: with `install_signal_handlers == false` nothing is
/// registered, nothing is logged and NO task is spawned — the embedder
/// cancels the token itself.
///
/// The tokio `Signal` streams are registered HERE, synchronously before
/// the task is spawned, so a registration failure surfaces through
/// `run`'s normal startup-error path (exit 1) instead of `.expect`
/// panicking inside the spawned task — whose `JoinHandle` the daemon
/// only discards on drain, which would leave the process running with
/// no shutdown handling at all.
fn install_shutdown_handler(
    opts: &Options,
    cancel: CancellationToken,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    if !owns_shutdown_handler(opts) {
        return Ok(None);
    }
    tracing::info!("Installing signal handlers");
    let sigint = signal(SignalKind::interrupt())
        .map_err(|e| anyhow::anyhow!("install SIGINT handler: {e}"))?;
    let sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("install SIGTERM handler: {e}"))?;
    Ok(Some(tokio::spawn(shutdown_handler(
        cancel, sigint, sigterm,
    ))))
}

/// Go: `main()`. Returns the process exit code (0 clean/canceled,
/// 1 for every Go `os.Exit(1)` path).
///
/// Cleanup invariant: from the first spawned task on, every Go exit path
/// either waits for its goroutines (`wg.Wait()`, main.go:509-513) or
/// cancels first (`cancel(); wg.Wait()`, e.g. main.go:369-372) before
/// `os.Exit`. The port funnels that through THIS wrapper: `run_inner`
/// records every task it spawns, and the wrapper cancels the token and
/// drains them on EVERY return path — startup errors included. In Go an
/// `os.Exit` discards goroutines by construction; on an embedder's
/// shared runtime a bare return would strand the healthz server and the
/// signal handler as leaked tasks.
pub async fn run(mut opts: Options, cancel: CancellationToken) -> anyhow::Result<i32> {
    // Pre-spawn phase: nothing has been spawned yet, so these early
    // returns cannot leak tasks.
    if opts.version {
        // Go: fmt.Fprintln(os.Stderr, version.Version)
        eprintln!("{VERSION}");
        return Ok(0);
    }

    // Log the config set via CLI flags (Go: %+v of opts).
    tracing::info!("CLI flags config: {opts:?}");

    // Validate flags.
    if opts.subnet_lease_renew_margin >= 24 * 60 || opts.subnet_lease_renew_margin <= 0 {
        tracing::error!("Invalid subnet-lease-renew-margin option, out of acceptable range");
        return Ok(1);
    }

    // Task-owning phase: whatever `run_inner` returns — Ok(code), a
    // startup `Err`, anything — cancel and drain here, exactly once.
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    let mut signal_task: Option<JoinHandle<()>> = None;
    let result = run_inner(&mut opts, &cancel, &mut tasks, &mut signal_task).await;
    cancel.cancel();
    drain(std::mem::take(&mut tasks)).await;
    drain_signal_task(signal_task.take()).await;
    result
}

/// Go's `main()` body after flag validation: creates the subnet manager,
/// installs shutdown handling, starts healthz, then runs the backend to
/// completion. Never cleans up itself — it records every spawned task
/// into `tasks`/`signal_task` and returns; `run` owns the cancel+drain.
async fn run_inner(
    opts: &mut Options,
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
    signal_task: &mut Option<JoinHandle<()>>,
) -> anyhow::Result<i32> {
    let sm = match subnet_mgr::create_subnet_manager(opts, cancel).await {
        Ok(sm) => sm,
        Err(e) => {
            // Go: `CONT_WHEN_CACHE_NOT_READY=true` + context.DeadlineExceeded
            // logs "Continuing anyway" and proceeds — but Go would then
            // dereference a nil manager in `sm.Name()` (upstream bug).
            // The Rust constructor returns no manager on failure, so both
            // branches exit; the timeout log is kept for parity.
            if std::env::var("CONT_WHEN_CACHE_NOT_READY").as_deref() == Ok("true")
                && subnet_mgr::is_timeout_like(&e)
            {
                tracing::error!("Timed out waiting for node controller sync. Continuing anyway.");
            } else {
                tracing::error!("Failed to create SubnetManager: {e}");
            }
            return Ok(1);
        }
    };
    tracing::info!("Created subnet manager: {}", sm.name());

    // Register for SIGINT and SIGTERM (Go: unconditional). Port deviation
    // for embedders (e.g. init-pro, which installs its own handlers via
    // `tokio::signal` and drives the token): with
    // `install_signal_handlers == false` neither the log nor the
    // `shutdownHandler` task happen; the embedder cancels `cancel`
    // itself. With the flag true (the default) the Go step order and log
    // messages are unchanged. Installation failures surface here as the
    // normal startup error (exit 1) instead of a panic inside the task.
    *signal_task = install_shutdown_handler(opts, cancel.clone())?;

    let ready = new_ready_flag();
    if opts.healthz_port > 0 {
        match start_healthz(opts, ready.clone(), cancel.clone()).await {
            Ok(Some((_addr, handle))) => tasks.push(handle),
            Ok(None) => {}
            Err(e) => {
                // Go panics (mustRunHealthz); the port exits 1.
                tracing::error!("Start healthz server error. {e}");
                return Ok(1);
            }
        }
    }

    // Fetch the network config (i.e. what backend to use etc..).
    let config = match subnet_mgr::get_config(cancel, sm.as_ref()).await {
        Ok(config) => config,
        // Go main.go:276: `if err == errCanceled { wg.Wait(); os.Exit(0) }`
        // — downcast the typed sentinel instead of comparing error text.
        Err(e) if e.is::<subnet_mgr::Canceled>() => return Ok(0),
        Err(e) => return Err(e),
    };

    // Get ip family stack.
    let ip_stack = match get_ip_family(config.enable_ipv4, config.enable_ipv6) {
        Ok(stack) => stack,
        Err(e) => {
            tracing::error!("{e}");
            return Ok(1);
        }
    };

    // From Kubernetes 1.30 kubeadm doesn't check if the br_netfilter
    // module is loaded and in case it's missing Flannel wrongly starts.
    if !config.enable_nftables {
        if let Err(e) = subnet_mgr::check_br_netfilter_paths(
            config.enable_ipv4,
            config.enable_ipv6,
            subnet_mgr::BR_NETFILTER_V4_PATH,
            subnet_mgr::BR_NETFILTER_V6_PATH,
        ) {
            tracing::error!("{e}");
            return Ok(1);
        }
    }

    // Work out which interface to use. Stored public IP annotations
    // override the CLI values first (Go: sm.GetStoredPublicIP).
    let (stored_public_ip, stored_public_ipv6) = sm.get_stored_public_ip(cancel).await;
    if !stored_public_ip.is_empty() {
        opts.public_ip = stored_public_ip;
    }
    if !stored_public_ipv6.is_empty() {
        opts.public_ipv6 = stored_public_ipv6;
    }

    let ext_iface = match iface_select::select_external_iface(opts, ip_stack).await {
        Ok(ext_iface) => ext_iface,
        Err(e) => {
            tracing::error!("{e}");
            return Ok(1);
        }
    };

    // Create a backend manager then use it to create the backend and
    // register the network with it.
    let mut bm = BackendManager::new(sm.clone() as Arc<dyn Manager>);
    default_registry(&mut bm);
    let be = match bm.create(&config.backend_type, Arc::new(ext_iface)) {
        Ok(be) => be,
        Err(e) => {
            tracing::error!("Error fetching backend: {e}");
            return Ok(1);
        }
    };

    let bn: Arc<dyn Network> = match be.register_network(cancel, &config).await {
        Ok(network) => Arc::from(network),
        Err(e) => {
            tracing::error!("Error registering network: {e}");
            return Ok(1);
        }
    };

    // Instantiate a TrafficManager to clean-up the rules of the backend
    // we don't use; ensures a clean state when flannel restarts with a
    // different choice.
    tracing::info!("Cleaning-up unused traffic manager rules");
    let cleanup_mngr = traffic::new_traffic_manager(!config.enable_nftables);
    if let Err(e) = cleanup_mngr.clean_up(cancel).await {
        tracing::error!("{e}");
        return Ok(1);
    }
    // Create TrafficManager based on whether we use iptables or nftables.
    let traffic_mngr = traffic::new_traffic_manager(config.enable_nftables);
    if let Err(e) = traffic_mngr.init(cancel).await {
        tracing::error!("{e}");
        return Ok(1);
    }

    // Set up ipMasq if needed.
    if opts.ip_masq {
        let prev_network =
            subnetfile::read_cidr_from_subnet_file(&opts.subnet_file, "FLANNEL_NETWORK");
        let prev_subnet =
            subnetfile::read_cidr_from_subnet_file(&opts.subnet_file, "FLANNEL_SUBNET");
        let prev_ipv6_network =
            subnetfile::read_ip6_cidr_from_subnet_file(&opts.subnet_file, "FLANNEL_IPV6_NETWORK");
        let prev_ipv6_subnet =
            subnetfile::read_ip6_cidr_from_subnet_file(&opts.subnet_file, "FLANNEL_IPV6_SUBNET");
        let result = traffic_mngr
            .setup_and_ensure_masq_rules(
                cancel,
                config.network,
                prev_subnet,
                prev_network,
                config.ipv6_network,
                prev_ipv6_subnet,
                prev_ipv6_network,
                bn.lease(),
                opts.iptables_resync_seconds,
                opts.ip_masq_random_fully_disable,
            )
            .await;
        if let Err(e) = result {
            tracing::error!("Failed to setup masq rules, {e}");
            return Ok(1);
        }
    }

    // Always enable forwarding rules (Docker >= 1.13 defaults the
    // FORWARD chain policy to DROP).
    if opts.iptables_forward_rules {
        traffic_mngr
            .setup_and_ensure_forward_rules(
                cancel,
                config.network,
                config.ipv6_network,
                opts.iptables_resync_seconds,
            )
            .await;
    }

    // Add blackhole route for the local CIDR in case the bridge plugin
    // is not enabled (e.g. Canal).
    if opts.blackhole_route {
        let period = Duration::from_secs(opts.iptables_resync_seconds.max(0) as u64);
        if config.enable_ipv4 {
            tasks.push(tokio::spawn(blackhole_v4_loop(
                cancel.clone(),
                bn.clone(),
                period,
            )));
        }
        if config.enable_ipv6 {
            tasks.push(tokio::spawn(blackhole_v6_loop(
                cancel.clone(),
                bn.clone(),
                period,
            )));
        }
    }

    let subnet = bn.lease().subnet;
    let ipv6_subnet = bn.lease().ipv6_subnet;
    let mtu = bn.mtu();
    let file_result = sm
        .handle_subnet_file(
            &opts.subnet_file,
            &config,
            opts.ip_masq,
            subnet,
            ipv6_subnet,
            mtu,
        )
        .await;
    if let Err(e) = file_result {
        // Continue, even though it failed.
        tracing::warn!("Failed to write subnet file: {e}");
    } else {
        tracing::info!("Wrote subnet file to {}", opts.subnet_file);
        // Traffic rules are set up and subnet.env is written: ready.
        ready.store(true, Ordering::SeqCst);
        tracing::info!("flannel is ready");
    }

    // Start "Running" the backend network; it blocks until cancelled.
    tracing::info!("Running backend.");
    let backend_bn = bn.clone();
    let backend_cancel = cancel.clone();
    let backend_task = tokio::spawn(async move {
        backend_bn.run(&backend_cancel).await;
    });

    if let Err(e) = systemd::sd_notify_ready() {
        tracing::error!("Failed to notify systemd the message READY=1 {e}");
    }

    // Go: `sm.CompleteLease(ctx, bn.Lease(), &wg)` — the error contract
    // lives in complete_lease_exit_code below.
    let lease_result = sm.complete_lease(cancel, bn.lease()).await;
    let exit_code = complete_lease_exit_code(cancel, lease_result);

    tracing::info!("Waiting for all goroutines to exit");
    let _ = backend_task.await;
    drain(std::mem::take(tasks)).await;
    drain_signal_task(signal_task.take()).await;
    tracing::info!("Exiting cleanly...");
    Ok(exit_code)
}

/// Go main.go:502-513: on a `CompleteLease` error Go ONLY logs it, and
/// cancels the context when the lease was "revoked" — the etcd local
/// manager's `errInterrupted` (pkg/subnet/etcd/local_manager.go:38,403),
/// compared by text there (main.go:503); the port downcasts the typed
/// `flannel_core::subnet::Interrupted` sentinel instead. Either way Go
/// then waits for all goroutines and exits 0 (main.go:509-513), so the
/// return is a constant 0: a CompleteLease failure NEVER fails the
/// process.
fn complete_lease_exit_code(cancel: &CancellationToken, result: anyhow::Result<()>) -> i32 {
    if let Err(e) = result {
        tracing::error!("CompleteLease execute error err: {e}");
        if e.is::<flannel_core::subnet::Interrupted>() {
            cancel.cancel();
        }
    }
    0
}

/// Go: `if opts.healthzPort > 0 { mustRunHealthz(...) }` (main.go:271).
/// `Ok(None)` when healthz is disabled. Go hands the raw int to
/// `net.JoinHostPort` (main.go:553); an out-of-u16-range value fails
/// `http.ListenAndServe`, Go logs "Start healthz server error." and
/// panics (main.go:587-591) — the port maps that onto the same
/// startup-error path (exit 1) instead of a silent `as u16` wrap.
async fn start_healthz(
    opts: &Options,
    ready: crate::healthz::ReadyFlag,
    cancel: CancellationToken,
) -> anyhow::Result<Option<(std::net::SocketAddr, JoinHandle<()>)>> {
    let Some(port) = healthz_listen_port(opts.healthz_port)? else {
        return Ok(None);
    };
    spawn_healthz(&opts.healthz_ip, port, ready, cancel)
        .await
        .map(Some)
}

/// The `i64 -> u16` healthz port conversion, extracted for tests: a
/// value outside u16 (e.g. `--healthz-port=70000`, which `as u16` would
/// silently wrap to 4464) is an error; `<= 0` keeps Go's "disabled".
fn healthz_listen_port(port: i64) -> anyhow::Result<Option<u16>> {
    if port <= 0 {
        return Ok(None);
    }
    u16::try_from(port)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("listen: invalid port {port}"))
}

/// Await all handles, ignoring panics (Go goroutine failures abort the
/// process; the port keeps going to land the clean-exit logs).
async fn drain(tasks: Vec<JoinHandle<()>>) {
    for task in tasks {
        let _ = task.await;
    }
}

/// Await the `shutdownHandler` task when flanneld owns the signals. In
/// embedder mode (`Options::install_signal_handlers == false`) it is
/// `None`: nothing was spawned, so there is nothing to wait for.
async fn drain_signal_task(signal_task: Option<JoinHandle<()>>) {
    if let Some(task) = signal_task {
        let _ = task.await;
    }
}

/// Go: `shutdownHandler` — wait for the context to be done or a signal
/// to arrive; in the signal case cancel the context (main.go:516-531).
/// `signal.Stop` is implicit: tokio deregisters when the signal streams
/// drop at task exit.
async fn shutdown_handler(cancel: CancellationToken, mut sigint: Signal, mut sigterm: Signal) {
    tokio::select! {
        _ = cancel.cancelled() => {
            tracing::info!("Stopping shutdownHandler...");
        }
        _ = async {
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
        } => {
            // Call cancel on the context to close everything down.
            cancel.cancel();
            tracing::info!("shutdownHandler sent cancel signal...");
        }
    }
}

/// Go's blackhole v4 loop: wait one resync period, then ensure the
/// blackhole route for the lease subnet, until cancelled.
async fn blackhole_v4_loop(cancel: CancellationToken, bn: Arc<dyn Network>, period: Duration) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(period) => {}
        }
        let subnet = bn.lease().subnet;
        let result = async {
            let nl = Netlink::new().await?;
            add_blackhole_v4_route(&nl, subnet).await
        }
        .await;
        if let Err(e) = result {
            tracing::error!("Failed to setup blackhole route, {e}");
        }
    }
}

/// Go's blackhole v6 loop (same one-period-first cadence).
async fn blackhole_v6_loop(cancel: CancellationToken, bn: Arc<dyn Network>, period: Duration) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(period) => {}
        }
        let subnet = bn.lease().ipv6_subnet;
        let result = async {
            let nl = Netlink::new().await?;
            add_blackhole_v6_route(&nl, subnet).await
        }
        .await;
        if let Err(e) = result {
            tracing::error!("Failed to setup blackhole route, {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flannel_core::subnet::Interrupted;

    #[test]
    fn default_options_keep_go_signal_parity() {
        // Go always installs the SIGINT/SIGTERM handlers, so the Go
        // parity default is `true`; only embedders opt out in code (no
        // CLI flag exists upstream).
        assert!(Options::default().install_signal_handlers);
        assert!(owns_shutdown_handler(&Options::default()));
    }

    #[test]
    fn embedder_opts_out_of_signal_handlers() {
        // Embedder mode: the gate is off, `run` spawns no
        // `shutdownHandler` task and the embedder drives the token.
        let opts = Options {
            install_signal_handlers: false,
            ..Default::default()
        };
        assert!(!owns_shutdown_handler(&opts));
    }

    // --- CompleteLease exit-code parity (Go main.go:502-513) ----------

    #[test]
    fn complete_lease_failure_logs_and_exits_zero_without_cancel() {
        // A plain CompleteLease failure (e.g. the kube PatchStatus call
        // erroring — kube.go:674-675, the only kube-mode error path) is
        // only logged; the context is NOT cancelled and the daemon still
        // exits 0.
        let cancel = CancellationToken::new();
        let code = complete_lease_exit_code(
            &cancel,
            Err(anyhow::anyhow!("patch node status: 500 InternalError")),
        );
        assert_eq!(code, 0, "Go main.go:513 exits 0 on CompleteLease error");
        assert!(
            !cancel.is_cancelled(),
            "non-interrupted errors don't cancel"
        );
    }

    #[test]
    fn complete_lease_interrupted_cancels_and_exits_zero() {
        // The revoked-lease flavor: the etcd local manager returns
        // errInterrupted (local_manager.go:403) and Go cancels the
        // context (main.go:503-506) — but the exit code stays 0
        // (main.go:513).
        let cancel = CancellationToken::new();
        let code = complete_lease_exit_code(&cancel, Err(anyhow::Error::new(Interrupted)));
        assert_eq!(code, 0);
        assert!(cancel.is_cancelled(), "interrupted cancels the context");
    }

    #[test]
    fn complete_lease_success_exits_zero_without_cancel() {
        let cancel = CancellationToken::new();
        assert_eq!(complete_lease_exit_code(&cancel, Ok(())), 0);
        assert!(!cancel.is_cancelled());
    }

    // --- healthz port range (Go main.go:553 + 587-591) ----------------

    #[test]
    fn healthz_port_out_of_u16_range_is_an_error_not_a_wrap() {
        // 70000 as u16 would silently wrap to 4464; Go fails
        // ListenAndServe ("address 70000: invalid port") and aborts.
        let err = healthz_listen_port(70000).unwrap_err().to_string();
        assert!(err.contains("invalid port 70000"), "{err}");
        // Go disables healthz for any `healthzPort <= 0` (main.go:271).
        assert_eq!(healthz_listen_port(-3).unwrap(), None);
        assert_eq!(healthz_listen_port(0).unwrap(), None);
        assert_eq!(healthz_listen_port(4464).unwrap(), Some(4464));
    }

    // --- typed sentinels ----------------------------------------------

    #[test]
    fn get_config_cancellation_downcasts_typed_sentinel() {
        // subnet_mgr::get_config returns the typed `Canceled` sentinel
        // (Go main.go:545 errCanceled); the daemon arm must match it by
        // downcast, not by the string "canceled" (which any error text
        // would satisfy).
        let err: anyhow::Error = subnet_mgr::Canceled.into();
        assert!(err.is::<subnet_mgr::Canceled>());
        assert!(!err.is::<Interrupted>());
    }
}
