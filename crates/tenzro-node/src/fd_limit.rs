//! The process's open-file limit.
//!
//! A node holds a RocksDB instance (many table files), a socket per peer and
//! per client, and its model and blob files at once. The common default soft
//! limit of 1024 is below that, and running out surfaces far from its cause:
//! an obscure "Too many open files" from storage, the network or a listener.
//! The node therefore raises its soft limit to the hard limit the operator's
//! system allows before it opens anything. It never raises the hard limit
//! (that needs privileges and is the operator's decision; the shipped service
//! unit sets it).

/// Raise the soft `RLIMIT_NOFILE` to the hard limit. Returns the resulting
/// soft limit, or an error naming the system call that failed.
#[cfg(unix)]
pub fn raise_to_hard_limit() -> Result<u64, String> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(format!(
            "getrlimit(RLIMIT_NOFILE) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // An unlimited hard limit is not a valid soft limit for open files on
    // every system; use the largest value the platform accepts instead.
    let target = if lim.rlim_max == libc::RLIM_INFINITY {
        65536
    } else {
        lim.rlim_max
    };
    // macOS refuses a soft limit above OPEN_MAX (10240, <sys/syslimits.h>),
    // which the libc crate does not export.
    #[cfg(target_os = "macos")]
    let target = target.min(10240 as libc::rlim_t);
    if lim.rlim_cur >= target {
        return Ok(lim.rlim_cur);
    }
    let raised = libc::rlimit {
        rlim_cur: target,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: `raised` is a valid rlimit; lowering or keeping the hard limit
    // and raising the soft limit up to it needs no privilege.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        return Err(format!(
            "setrlimit(RLIMIT_NOFILE, {}) failed: {}",
            target,
            std::io::Error::last_os_error()
        ));
    }
    Ok(target)
}

#[cfg(not(unix))]
pub fn raise_to_hard_limit() -> Result<u64, String> {
    Ok(u64::MAX)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_soft_limit_is_raised_and_reported() {
        let soft = raise_to_hard_limit().expect("raise");
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        assert_eq!(soft, lim.rlim_cur);
        assert!(
            lim.rlim_cur == lim.rlim_max
                || lim.rlim_max == libc::RLIM_INFINITY
                || cfg!(target_os = "macos")
        );
    }
}
