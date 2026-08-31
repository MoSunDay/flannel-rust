//! flannel CNI meta-plugin library.
//!
//! Rust port of the flannel CNI meta-plugin (upstream project
//! `flannel-io/cni-plugin`): it reads `/run/flannel/subnet.env` written by
//! `flanneld`, builds a `bridge` + `host-local` delegate configuration for
//! the node's pod subnet, delegates ADD/DEL/CHECK to the real CNI plugin
//! found on `CNI_PATH`, and optionally installs the `FLANNEL-POSTRTG-CHAIN-01`
//! masquerade rules when `FLANNEL_IPMASQ=true`.

pub mod delegate;
pub mod masq;
pub mod netconf;
pub mod skel;

use anyhow::Result;

/// CNI plugin version reported by VERSION.
pub const SUPPORTED_VERSIONS: &[&str] = &["0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"];

/// CNI ADD: build the delegate config, delegate, then optionally set up masq.
pub fn cmd_add(args: &skel::CniArgs, conf_bytes: &[u8]) -> Result<serde_json::Value> {
    let conf = netconf::load_flannel_net_conf(conf_bytes)?;
    let env_path = netconf::default_subnet_env_path();
    let env = netconf::load_flannel_subnet_env(&env_path)?;
    let delegate_conf = netconf::build_delegate_conf(&conf, &env)?;
    let plugin = delegate::find_plugin(&args.path, &delegate_conf["type"])?;
    let result = delegate::delegate_add(&delegate_conf, &plugin, args)?;
    if env.ipmasq {
        masq::ip_masq_config(
            env.network.as_ref(),
            env.subnet.as_ref(),
            env.ipv6_network.as_ref(),
            env.ipv6_subnet.as_ref(),
        )?;
    }
    Ok(result)
}

/// CNI DEL: delegate; always succeed (DEL must be best-effort and
/// idempotent, see the CNI spec).
pub fn cmd_del(args: &skel::CniArgs, conf_bytes: &[u8]) -> Result<()> {
    let conf = netconf::load_flannel_net_conf(conf_bytes)?;
    let delegate_conf = match netconf::load_flannel_subnet_env(&netconf::default_subnet_env_path())
        .and_then(|env| netconf::build_delegate_conf(&conf, &env))
    {
        Ok(delegate_conf) => delegate_conf,
        Err(e) => {
            // Missing *or* broken subnet.env (flanneld may have
            // removed/truncated it, or it may lack FLANNEL_SUBNET):
            // none of that may fail cleanup, so fall back to the
            // delegate overrides alone and let the plugin tear down.
            eprintln!(
                "flannel-cni: DEL: subnet.env unusable ({e:#}); using delegate overrides only"
            );
            netconf::minimal_delegate_conf(&conf)?
        }
    };
    let plugin = delegate::find_plugin(&args.path, &delegate_conf["type"])?;
    match delegate::delegate_del(&delegate_conf, &plugin, args) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!("DEL: delegate reported {e:#} (treating as success)");
            Ok(())
        }
    }
}

/// CNI CHECK: delegate to the delegate plugin.
pub fn cmd_check(args: &skel::CniArgs, conf_bytes: &[u8]) -> Result<()> {
    let conf = netconf::load_flannel_net_conf(conf_bytes)?;
    let env = netconf::load_flannel_subnet_env(&netconf::default_subnet_env_path())?;
    let delegate_conf = netconf::build_delegate_conf(&conf, &env)?;
    let plugin = delegate::find_plugin(&args.path, &delegate_conf["type"])?;
    delegate::delegate_check(&delegate_conf, &plugin, args)
}

/// CNI VERSION: report supported CNI spec versions.
pub fn cmd_version(conf_bytes: &[u8]) -> serde_json::Value {
    let version = netconf::load_flannel_net_conf(conf_bytes)
        .map(|c| c.cni_version)
        .unwrap_or_else(|_| "1.0.0".to_string());
    serde_json::json!({
        "cniVersion": version,
        "supportedVersions": SUPPORTED_VERSIONS,
    })
}
