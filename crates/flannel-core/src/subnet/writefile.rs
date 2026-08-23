//! Port of `WriteSubnetFile` (pkg/subnet/subnet.go, upstream cdf76059) plus
//! the writeFile helper of pkg/subnet/writefile_other.go (renameio-based
//! atomic write, ported as `crate::utils::write_file_atomic`).

use crate::ip::{IP4Net, IP6Net};
use crate::subnet::config::Config;
use crate::utils::write_file_atomic;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

/// Go: `os.MkdirAll(dir, 0755)`. Every created component gets mode 0755
/// (subject to the umask, exactly like Go).
fn mkdir_all_0755(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o755);
    builder.create(dir)
}

/// Go: `WriteSubnetFile`. Writes the subnet.env file atomically with mode
/// 0644, creating the parent directory (mode 0755) first.
pub fn write_subnet_file(
    path: &str,
    config: &Config,
    ip_masq: bool,
    sn: IP4Net,
    ipv6sn: IP6Net,
    mtu: u32,
) -> anyhow::Result<()> {
    // Go: dir := filepath.Dir(path) (a bare filename yields "."), then
    // os.MkdirAll. Rust's parent() of a bare filename is Some("").
    if let Some(dir) = Path::new(path).parent() {
        mkdir_all_0755(dir)?;
    }

    let mut b = String::new();

    if config.enable_ipv4 {
        // Write out the first usable IP by incrementing sn.IP by one.
        let mut sn = sn;
        sn.increment_ip();
        b.push_str(&format!(
            "FLANNEL_NETWORK={}\nFLANNEL_SUBNET={}\n",
            config.network, sn
        ));
    }
    if config.enable_ipv6 {
        // Write out the first usable IP by incrementing ipv6sn.IP by one.
        let mut ipv6sn = ipv6sn;
        ipv6sn.increment_ip();
        b.push_str(&format!(
            "FLANNEL_IPV6_NETWORK={}\nFLANNEL_IPV6_SUBNET={}\n",
            config.ipv6_network, ipv6sn
        ));
    }

    b.push_str(&format!("FLANNEL_MTU={mtu}\nFLANNEL_IPMASQ={ip_masq}\n"));

    write_file_atomic(path, b.as_bytes(), 0o644)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_config() -> Config {
        Config {
            enable_ipv4: true,
            network: "10.100.0.0/16".parse().unwrap(),
            ..Default::default()
        }
    }

    fn v6_config() -> Config {
        Config {
            enable_ipv6: true,
            ipv6_network: "fc00::/48".parse().unwrap(),
            ..Default::default()
        }
    }

    fn dual_config() -> Config {
        Config {
            enable_ipv4: true,
            enable_ipv6: true,
            network: "10.100.0.0/16".parse().unwrap(),
            ipv6_network: "fc00::/48".parse().unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn v4_only_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subnet.env");
        let sn: IP4Net = "10.100.5.0/24".parse().unwrap();
        write_subnet_file(
            path.to_str().unwrap(),
            &v4_config(),
            true,
            sn,
            IP6Net::default(),
            1450,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "FLANNEL_NETWORK=10.100.0.0/16\n\
             FLANNEL_SUBNET=10.100.5.1/24\n\
             FLANNEL_MTU=1450\n\
             FLANNEL_IPMASQ=true\n"
        );
    }

    #[test]
    fn v6_only_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subnet.env");
        let sn6: IP6Net = "fc00:0:0:5::/64".parse().unwrap();
        write_subnet_file(
            path.to_str().unwrap(),
            &v6_config(),
            false,
            IP4Net::default(),
            sn6,
            1500,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "FLANNEL_IPV6_NETWORK=fc00::/48\n\
             FLANNEL_IPV6_SUBNET=fc00:0:0:5::1/64\n\
             FLANNEL_MTU=1500\n\
             FLANNEL_IPMASQ=false\n"
        );
    }

    #[test]
    fn dual_stack_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subnet.env");
        let sn: IP4Net = "10.100.5.0/24".parse().unwrap();
        let sn6: IP6Net = "fc00:0:0:5::/64".parse().unwrap();
        write_subnet_file(path.to_str().unwrap(), &dual_config(), true, sn, sn6, 8950).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "FLANNEL_NETWORK=10.100.0.0/16\n\
             FLANNEL_SUBNET=10.100.5.1/24\n\
             FLANNEL_IPV6_NETWORK=fc00::/48\n\
             FLANNEL_IPV6_SUBNET=fc00:0:0:5::1/64\n\
             FLANNEL_MTU=8950\n\
             FLANNEL_IPMASQ=true\n"
        );
    }

    #[test]
    fn creates_parent_dirs_with_file_mode_0644() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/subnet.env");
        assert!(!dir.path().join("a").exists());
        let sn: IP4Net = "10.100.5.0/24".parse().unwrap();
        write_subnet_file(
            path.to_str().unwrap(),
            &v4_config(),
            false,
            sn,
            IP6Net::default(),
            1500,
        )
        .unwrap();
        assert!(dir.path().join("a/b/c").is_dir());
        // Go: writeFile(path, b, 0644). Exact mode, umask-independent.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn bare_filename_uses_current_dir() {
        // Go: filepath.Dir("subnet.env") == "."; parent() == Some("").
        let dir = tempfile::tempdir().unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let sn: IP4Net = "10.100.5.0/24".parse().unwrap();
        let res = write_subnet_file(
            "subnet.env",
            &v4_config(),
            true,
            sn,
            IP6Net::default(),
            1500,
        );
        std::env::set_current_dir(&saved).unwrap();
        res.unwrap();
        assert!(dir.path().join("subnet.env").exists());
    }
}
