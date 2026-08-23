//! The daemon orchestration: port of flannel `main.go` `main()` plus
//! `shutdownHandler` (upstream cdf76059), in Go's exact step order and
//! with Go's log messages.

use crate::healthz::{new_ready_flag, spawn_healthz};
use crate::{iface_select, subnet_mgr, subnetfile, systemd, traffic, Options, VERSION};
use flannel_core::backend::{default_registry, BackendManager, Network};
use flannel_core::ip::iface::{add_blackhole_v4_route, add_blackhole_v6_route, Netlink};
use flannel_core::ipmatch::get_ip_family;
use flannel_core::subnet::Manager;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Go: `main()`. Returns the process exit code (0 clean/canceled,
/// 1 for every Go `os.Exit(1)` path).
pub async fn run(mut opts: Options, cancel: CancellationToken) -> anyhow::Result<i32> {
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

    let sm = match subnet_mgr::create_subnet_manager(&opts, &cancel).await {
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

    // Register for SIGINT and SIGTERM.
    tracing::info!("Installing signal handlers");
    let signal_task = tokio::spawn(shutdown_handler(cancel.clone()));

    let ready = new_ready_flag();
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    if opts.healthz_port > 0 {
        match spawn_healthz(
            &opts.healthz_ip,
            opts.healthz_port as u16,
            ready.clone(),
            cancel.clone(),
        )
        .await
        {
            Ok((_addr, handle)) => tasks.push(handle),
            Err(e) => {
                // Go panics (mustRunHealthz); the port exits 1.
                tracing::error!("Start healthz server error. {e}");
                cancel.cancel();
                drain(tasks).await;
                let _ = signal_task.await;
                return Ok(1);
            }
        }
    }

    // Fetch the network config (i.e. what backend to use etc..).
    let config = match subnet_mgr::get_config(&cancel, sm.as_ref()).await {
        Ok(config) => config,
        Err(e) if e.to_string() == "canceled" => {
            drain(tasks).await;
            let _ = signal_task.await;
            return Ok(0);
        }
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
    let (stored_public_ip, stored_public_ipv6) = sm.get_stored_public_ip(&cancel).await;
    if !stored_public_ip.is_empty() {
        opts.public_ip = stored_public_ip;
    }
    if !stored_public_ipv6.is_empty() {
        opts.public_ipv6 = stored_public_ipv6;
    }

    let ext_iface = match iface_select::select_external_iface(&opts, ip_stack).await {
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
            return Ok(exit_after_cancel(cancel, tasks, signal_task).await);
        }
    };

    let bn: Arc<dyn Network> = match be.register_network(&cancel, &config).await {
        Ok(network) => Arc::from(network),
        Err(e) => {
            tracing::error!("Error registering network: {e}");
            return Ok(exit_after_cancel(cancel, tasks, signal_task).await);
        }
    };

    // Instantiate a TrafficManager to clean-up the rules of the backend
    // we don't use; ensures a clean state when flannel restarts with a
    // different choice.
    tracing::info!("Cleaning-up unused traffic manager rules");
    let cleanup_mngr = traffic::new_traffic_manager(!config.enable_nftables);
    if let Err(e) = cleanup_mngr.clean_up(&cancel).await {
        tracing::error!("{e}");
        return Ok(exit_after_cancel(cancel, tasks, signal_task).await);
    }
    // Create TrafficManager based on whether we use iptables or nftables.
    let traffic_mngr = traffic::new_traffic_manager(config.enable_nftables);
    if let Err(e) = traffic_mngr.init(&cancel).await {
        tracing::error!("{e}");
        return Ok(exit_after_cancel(cancel, tasks, signal_task).await);
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
                &cancel,
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
            return Ok(exit_after_cancel(cancel, tasks, signal_task).await);
        }
    }

    // Always enable forwarding rules (Docker >= 1.13 defaults the
    // FORWARD chain policy to DROP).
    if opts.iptables_forward_rules {
        traffic_mngr
            .setup_and_ensure_forward_rules(
                &cancel,
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

    if let Err(e) = sm.complete_lease(&cancel, bn.lease()).await {
        tracing::error!("CompleteLease execute error err: {e}");
        if e.to_string().eq_ignore_ascii_case("interrupted") {
            // The lease was "revoked" - shut everything down.
            cancel.cancel();
        }
    }

    tracing::info!("Waiting for all goroutines to exit");
    let _ = backend_task.await;
    drain(tasks).await;
    let _ = signal_task.await;
    tracing::info!("Exiting cleanly...");
    Ok(0)
}

/// Go error paths run `cancel(); wg.Wait(); os.Exit(1)`: cancel, wait
/// for the spawned goroutines (healthz, blackhole loops, signal
/// handler), then exit 1.
async fn exit_after_cancel(
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    signal_task: JoinHandle<()>,
) -> i32 {
    cancel.cancel();
    drain(tasks).await;
    let _ = signal_task.await;
    1
}

/// Await all handles, ignoring panics (Go goroutine failures abort the
/// process; the port keeps going to land the clean-exit logs).
async fn drain(tasks: Vec<JoinHandle<()>>) {
    for task in tasks {
        let _ = task.await;
    }
}

/// Go: `shutdownHandler` — wait for cancellation or SIGINT/SIGTERM; in
/// the signal case cancel the token. `signal.Stop` is implicit: tokio
/// deregisters when the signal futures drop at task exit.
async fn shutdown_handler(cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {
            tracing::info!("Stopping shutdownHandler...");
        }
        _ = wait_for_shutdown_signal() => {
            // Call cancel on the context to close everything down.
            cancel.cancel();
            tracing::info!("shutdownHandler sent cancel signal...");
        }
    }
}

async fn wait_for_shutdown_signal() {
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
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
