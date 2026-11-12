//! Probing for a TPM leaves the TPM limits unset: a node checks for its
//! hardware key store before it reads the limits from its configuration.

#![cfg(any(target_os = "linux", windows))]

use std::time::Duration;

use tenzro_device_key::tpm_exec::{Limits, configure};

#[test]
fn limits_from_the_configuration_apply_after_the_probe() {
    let _ = tenzro_device_key::signer::platform_backend();
    let configured = Limits {
        call_timeout: Duration::from_secs(10),
        signs_per_second: 30,
        quotes_per_second: Limits::default().quotes_per_second + 3,
        ..Limits::default()
    };
    configure(configured).expect("the probe must not fix the default limits");
}
