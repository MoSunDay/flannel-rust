//! External interface selection. Port of the interface-resolution block
//! of flannel main.go (upstream cdf76059): default-gateway lookup when
//! nothing is specified, then explicit `--iface` names in order, then
//! `--iface-regex` patterns in order, then the `--iface-can-reach`
//! fallback. Log messages and final error texts match Go.

use crate::Options;
use flannel_core::backend::ExternalInterface;
use flannel_core::ip::Netlink;
use flannel_core::ipmatch::{lookup_ext_iface, PublicIPOpts};

/// Run the Go selection algorithm. Error strings carry the exact Go
/// log-line text ("Failed to find any valid interface to use: ..." /
/// "Failed to find interface to use that matches the interfaces and/or
/// regexes provided") so the daemon can log them verbatim.
pub async fn select_external_iface(
    opts: &Options,
    ip_stack: i32,
) -> anyhow::Result<ExternalInterface> {
    let public_opts = PublicIPOpts {
        public_ip: opts.public_ip.clone(),
        public_ip_v6: opts.public_ipv6.clone(),
    };

    // Rust deviation from Go: netlink access goes through an explicit
    // connection (`Netlink`), constructed once here instead of per call.
    let no_explicit =
        opts.iface.is_empty() && opts.iface_regex.is_empty() && opts.iface_can_reach.is_empty();
    let nl = Netlink::new().await.map_err(|e| {
        if no_explicit {
            anyhow::anyhow!("Failed to find any valid interface to use: {e}")
        } else {
            anyhow::anyhow!(
                "Failed to find interface to use that matches the interfaces \
                 and/or regexes provided"
            )
        }
    })?;

    // Check the default interface only if no interfaces are specified.
    if no_explicit {
        // Go passes publicIP (or publicIPv6) as the *ifname* argument
        // here; empty strings fall through to the default-route lookup.
        let ifname = if !opts.public_ip.is_empty() {
            opts.public_ip.as_str()
        } else {
            opts.public_ipv6.as_str()
        };
        return lookup_ext_iface(&nl, ifname, "", "", ip_stack, &public_opts)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to find any valid interface to use: {e}"));
    }

    let mut ext_iface: Option<ExternalInterface> = None;

    // Check explicitly specified interfaces.
    for iface in &opts.iface {
        match lookup_ext_iface(&nl, iface, "", "", ip_stack, &public_opts).await {
            Ok(found) => {
                ext_iface = Some(found);
                break;
            }
            Err(e) => {
                tracing::info!("Could not find valid interface matching {iface}: {e}");
            }
        }
    }

    // Check interfaces that match any specified regexes.
    if ext_iface.is_none() {
        for regex in &opts.iface_regex {
            match lookup_ext_iface(&nl, "", regex, "", ip_stack, &public_opts).await {
                Ok(found) => {
                    ext_iface = Some(found);
                    break;
                }
                Err(e) => {
                    tracing::info!("Could not find valid interface matching {regex}: {e}");
                }
            }
        }
    }

    if ext_iface.is_none() && !opts.iface_can_reach.is_empty() {
        match lookup_ext_iface(&nl, "", "", &opts.iface_can_reach, ip_stack, &public_opts).await {
            Ok(found) => ext_iface = Some(found),
            Err(e) => {
                tracing::info!(
                    "Could not find valid interface matching ifaceCanReach: {}: {e}",
                    opts.iface_can_reach
                );
            }
        }
    }

    // Exit if any of the specified interfaces do not match.
    ext_iface.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to find interface to use that matches the interfaces \
             and/or regexes provided"
        )
    })
}
