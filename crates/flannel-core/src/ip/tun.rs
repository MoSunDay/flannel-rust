//! Port of pkg/ip/tun.go (upstream cdf76059): opening a TUN device.
//!
//! Go deviation: Go leaks the opened file when the TUNSETIFF ioctl
//! fails (the error path never closes it); the Rust `OwnedFd` closes it
//! on drop instead.

use anyhow::bail;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Go `tunDevice`.
/// NUL-terminated path for `libc::open`.
const TUN_DEVICE: &[u8] = b"/dev/net/tun\0";
/// Go `ifnameSize`.
const IFNAME_SIZE: usize = 16;

/// Go `ifreqFlags`: the name + flags prefix of `struct ifreq`.
#[repr(C)]
struct IfreqFlags {
    ifrn_name: [u8; IFNAME_SIZE],
    ifru_flags: u16,
}

/// Go `fromZeroTerm`.
fn from_zero_term(s: &[u8]) -> String {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

/// Go `OpenTun`: opens /dev/net/tun and issues TUNSETIFF with
/// IFF_TUN | IFF_NO_PI for `dev_name` (a pattern like "flannel%d").
/// The kernel resolves the pattern and writes the assigned interface
/// name back into the ifreq; it is returned alongside the fd. Closing
/// the fd removes the tun device again.
pub fn open_tun(dev_name: &str) -> anyhow::Result<(OwnedFd, String)> {
    let raw = unsafe { libc::open(TUN_DEVICE.as_ptr().cast::<libc::c_char>(), libc::O_RDWR) };
    if raw < 0 {
        bail!("open /dev/net/tun: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut ifr = IfreqFlags {
        ifrn_name: [0; IFNAME_SIZE],
        ifru_flags: 0,
    };
    // Go: copy(ifr.IfrnName[:len(ifr.IfrnName)-1], []byte(name+"\000")).
    let name = dev_name.as_bytes();
    let n = name.len().min(IFNAME_SIZE - 1);
    ifr.ifrn_name[..n].copy_from_slice(&name[..n]);
    ifr.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut ifr) };
    if ret < 0 {
        bail!("ioctl TUNSETIFF: {}", std::io::Error::last_os_error());
    }

    Ok((fd, from_zero_term(&ifr.ifrn_name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Container CI runs as root with /dev/net/tun available; anywhere
    /// else the test skips itself instead of failing.
    #[test]
    fn open_tun_flannel_pattern() {
        let can_tun =
            unsafe { libc::geteuid() } == 0 && std::path::Path::new("/dev/net/tun").exists();
        if !can_tun {
            eprintln!("skipping open_tun test: needs root and /dev/net/tun");
            return;
        }
        let (fd, name) = open_tun("flannel%d").expect("open_tun(flannel%d)");
        assert!(name.starts_with("flannel"), "unexpected tun name {name}");
        drop(fd); // closing the fd removes the tun device
    }
}
