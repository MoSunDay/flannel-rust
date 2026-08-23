use super::*;
use crate::lease::LeaseWatchResult;
use crate::subnet::manager::{Ctx, Manager};
use std::time::UNIX_EPOCH;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn canned_lease() -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: IP4Net::new(IP4::from_octets(10, 244, 1, 0), 24),
        ipv6_subnet: crate::ip::IP6Net::default(),
        attrs: LeaseAttrs {
            public_ip: IP4::from_octets(192, 168, 77, 10),
            backend_type: "ipip".to_string(),
            ..Default::default()
        },
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

#[test]
fn expected_tunnel_mtu_subtracts_ipip_header() {
    assert_eq!(expected_tunnel_mtu(1500, "eth0").unwrap(), 1480);
    assert_eq!(expected_tunnel_mtu(1450, "eth0").unwrap(), 1430);
}

#[test]
fn expected_tunnel_mtu_rejects_too_small_iface() {
    let err = expected_tunnel_mtu(20, "eth0").err().unwrap();
    assert_eq!(
        err.to_string(),
        "MTU 20 of iface eth0 is too small for ipip mode to work"
    );
    assert!(expected_tunnel_mtu(15, "eth0").is_err());
}

#[test]
fn config_parses_direct_routing_flag() {
    let none: IPIPBackendConfig = serde_json::from_str("{}").unwrap();
    assert!(!none.direct_routing);
    let on: IPIPBackendConfig = serde_json::from_str(r#"{"DirectRouting": true}"#).unwrap();
    assert!(on.direct_routing);
    assert!(serde_json::from_str::<IPIPBackendConfig>("not-json").is_err());
}

#[tokio::test]
async fn register_network_rejects_bad_backend_json() {
    struct DummyManager;
    impl Manager for DummyManager {
        fn get_network_config<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
            unimplemented!()
        }
        fn handle_subnet_file<'a>(
            &'a self,
            _p: &'a str,
            _c: &'a Config,
            _m: bool,
            _s: IP4Net,
            _s6: crate::ip::IP6Net,
            _mtu: u32,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn acquire_lease<'a>(
            &'a self,
            _c: Ctx<'a>,
            _a: &'a LeaseAttrs,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            unimplemented!()
        }
        fn renew_lease<'a>(
            &'a self,
            _c: Ctx<'a>,
            _l: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            unimplemented!()
        }
        fn watch_lease<'a>(
            &'a self,
            _c: Ctx<'a>,
            _s: IP4Net,
            _s6: crate::ip::IP6Net,
            _t: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn watch_leases<'a>(
            &'a self,
            _c: Ctx<'a>,
            _t: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn complete_lease<'a>(
            &'a self,
            _c: Ctx<'a>,
            _l: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn get_stored_mac_addresses<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
            unimplemented!()
        }
        fn get_stored_public_ip<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
            unimplemented!()
        }
        fn name(&self) -> String {
            "dummy".to_string()
        }
    }

    let be = IPIPBackend {
        sm: Arc::new(DummyManager),
        ei: Arc::new(ExternalInterface {
            iface_index: 1,
            iface_name: "lo".to_string(),
            iface_addr: Some("127.0.0.1".parse().unwrap()),
            ext_addr: Some("127.0.0.1".parse().unwrap()),
            ..Default::default()
        }),
    };
    // Valid JSON that does not match IPIPBackendConfig (number where
    // a bool is expected); RawValue itself requires valid JSON.
    let config = Config {
        enable_ipv4: true,
        backend: Some(
            serde_json::value::RawValue::from_string(r#"{"DirectRouting": 1}"#.into()).unwrap(),
        ),
        ..Default::default()
    };

    let token = CancellationToken::new();
    let err = be.register_network(&token, &config).await.err().unwrap();
    assert!(
        err.to_string()
            .starts_with("error decoding IPIP backend config:"),
        "got: {err}"
    );
}

#[tokio::test]
async fn get_route_builds_onlink_tunnel_route() {
    // direct_routing disabled: no netlink lookup is performed, so a
    // default (never-used) handle is enough to build the closure.
    let nl = Netlink::new().await.unwrap();
    let f = ipip_get_route(nl, false, 42, 7);
    let spec = f(&canned_lease()).await;
    assert_eq!(spec.dst, "10.244.1.0".parse::<IpAddr>().unwrap());
    assert_eq!(spec.prefix_len, 24);
    assert_eq!(spec.gateway, "192.168.77.10".parse::<IpAddr>().unwrap());
    assert_eq!(spec.link_index, 42); // tunnel device
    assert!(spec.onlink); // Go FLAG_ONLINK
    assert_eq!(spec.family, AddressFamily::Inet);
}
