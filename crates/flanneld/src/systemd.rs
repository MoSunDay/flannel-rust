//! sd_notify support. Port of the `daemon.SdNotify(false, "READY=1")`
//! call in flannel main.go (go-systemd semantics, upstream cdf76059).
//!
//! Protocol: if `$NOTIFY_SOCKET` is set, send the state string as one
//! unix datagram to that socket. A leading `@` names an abstract-namespace
//! socket. When the variable is unset Go's SdNotify is a no-op
//! (`(false, nil)`); errors are returned and logged by the caller.

use nix::sys::socket::{sendto, socket, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr};
use std::os::fd::AsRawFd;
use std::path::Path;

/// Send `READY=1` to `$NOTIFY_SOCKET`. `Ok(())` also covers the
/// not-running-under-systemd case (Go: no NOTIFY_SOCKET -> no-op).
pub fn sd_notify_ready() -> anyhow::Result<()> {
    let socket_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(()),
    };
    send_state(&socket_path, "READY=1")
}

/// Go `daemon.SdNotify` core: datagram `state` to `socket_name`.
fn send_state(socket_name: &str, state: &str) -> anyhow::Result<()> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| anyhow::anyhow!("failed to create notify socket: {e}"))?;

    // Go: a leading '@' switches to the abstract namespace.
    let addr = if let Some(abstract_name) = socket_name.strip_prefix('@') {
        UnixAddr::new_abstract(abstract_name.as_bytes())
            .map_err(|e| anyhow::anyhow!("bad abstract notify socket: {e}"))?
    } else {
        UnixAddr::new(Path::new(socket_name))
            .map_err(|e| anyhow::anyhow!("bad notify socket path: {e}"))?
    };

    sendto(fd.as_raw_fd(), state.as_bytes(), &addr, MsgFlags::empty())
        .map_err(|e| anyhow::anyhow!("failed to send notify message: {e}"))?;
    Ok(())
}
