//! Asking NVML again and again must not grow the process.
//!
//! One test in its own binary, so no other test opens or closes anything while
//! the descriptors and threads are counted.
#![cfg(all(target_os = "linux", feature = "nvidia-gpu"))]

use tenzro_tee::nvidia_device::collect_local;
use tenzro_tee::nvml::Nvml;

fn entries(dir: &str) -> usize {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir} is readable: {e}"))
        .count()
}

#[test]
fn repeated_use_leaves_no_descriptors_or_threads_behind() {
    let nonce = [7u8; 32];
    // The first use loads the library, which opens what it needs once.
    let _ = Nvml::open();
    let _ = collect_local(&nonce);
    let descriptors = entries("/proc/self/fd");
    let threads = entries("/proc/self/task");

    for _ in 0..32 {
        let _ = Nvml::open();
        let _ = collect_local(&nonce);
    }

    assert_eq!(
        entries("/proc/self/fd"),
        descriptors,
        "open descriptors grew over repeated NVML use"
    );
    assert_eq!(
        entries("/proc/self/task"),
        threads,
        "threads grew over repeated NVML use"
    );
}
