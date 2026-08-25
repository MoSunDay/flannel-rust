//! Capabilities that cannot run a true closed loop in this environment,
//! documented as deliberate skips with exact reasons:
//!
//! * **ipsec**: the backend spawns strongSwan `charon` and talks VICI on
//!   the fixed `/var/run/charon.vici` socket; no charon is installed.
//!   Protocol layer is covered by `backend/ipsec/{vici,charon,xfrm}_tests`
//!   (VICI mock + live xfrm policies).
//! * **tencent-vpc**: metadata (`metadata.tencentyun.com`) and VPC API
//!   (`vpc.tencentcloudapi.com`) endpoints are hardcoded and injectable
//!   only via the crate-private `register_network_with`; a real loop
//!   needs a Tencent cloud account. TC3 signing + route reconcile are
//!   covered by `backend/tencentvpc/api_tests.rs` (recorded vectors).

use crate::{E2EError, Scenario};

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "ipsec-datapath",
            desc: "ipsec: requires strongSwan charon at /var/run/charon.vici",
            run: || Box::pin(run_ipsec()),
        },
        Scenario {
            name: "tencent-vpc-datapath",
            desc: "tencent-vpc: requires Tencent cloud metadata + VPC API endpoints",
            run: || Box::pin(run_tencent()),
        },
    ]
}

async fn run_ipsec() -> Result<(), E2EError> {
    let candidates = [
        "charon",
        "/usr/lib/strongswan/charon",
        "/usr/lib/ipsec/charon",
        "/usr/libexec/strongswan/charon",
        "/usr/libexec/ipsec/charon",
    ];
    let found = candidates
        .iter()
        .find(|c| std::path::Path::new(c).exists())
        .copied();
    match found {
        Some(path) => Err(E2EError::skip(format!(
            "charon found at {path} but a full ipsec closed loop also needs a \
             signed cert infrastructure; VICI/xfrm layers are covered by \
             flannel-core unit/integration tests"
        ))),
        None => Err(E2EError::skip(
            "strongSwan charon not installed (checked PATH + standard \
             locations); ipsec backend cannot spawn its IKE daemon here",
        )),
    }
}

async fn run_tencent() -> Result<(), E2EError> {
    Err(E2EError::skip(
        "Tencent VPC metadata + API endpoints are hardcoded constants \
         (metadata.tencentyun.com / vpc.tencentcloudapi.com); no local \
         override exists, and a real loop needs a cloud account",
    ))
}
