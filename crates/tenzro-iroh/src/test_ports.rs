//! Loopback ports for tests that must name a port before something binds it.
//!
//! Asking the system for port 0 and releasing the socket leaves the port free
//! for anyone: another test's probe, or the local port of an outgoing
//! connection, can take it before the test binds it. The ports here come from
//! a per-process sequence below every platform's default ephemeral range
//! (32768 and up on Linux, 49152 and up on macOS and Windows), so the system
//! never hands one out on its own, and no two calls in one process return the
//! same port. The sequence starts at an offset taken from the process id, so
//! test processes running side by side walk different ports. A port some
//! other program holds is passed over.

use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};

const FIRST: u16 = 20_000;
const SPAN: u16 = 12_000;
/// Distance between the first ports of processes whose ids differ by one;
/// more than any one test process asks for.
const STRIDE: u32 = 97;

static NEXT: AtomicU16 = AtomicU16::new(0);

fn next_port(free: impl Fn(u16) -> bool) -> u16 {
    let offset = (std::process::id().wrapping_mul(STRIDE) % u32::from(SPAN)) as u16;
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(n < SPAN, "no free loopback port left for this test process");
        let port = FIRST + (offset + n) % SPAN;
        if free(port) {
            return port;
        }
    }
}

/// A loopback TCP port no other caller in this process is given.
pub fn tcp() -> u16 {
    next_port(|port| TcpListener::bind(("127.0.0.1", port)).is_ok())
}

/// A loopback UDP port no other caller in this process is given.
pub fn udp() -> u16 {
    next_port(|port| UdpSocket::bind(("127.0.0.1", port)).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_port_is_handed_out_twice_and_none_is_ephemeral() {
        let ports: Vec<u16> = (0..64)
            .map(|i| if i % 2 == 0 { tcp() } else { udp() })
            .collect();
        let mut unique = ports.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ports.len(), "{ports:?}");
        assert!(
            ports.iter().all(|p| (FIRST..FIRST + SPAN).contains(p)),
            "{ports:?}"
        );
    }
}
