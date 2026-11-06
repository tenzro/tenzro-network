//! Python binding over the device-key core shared with the Node.js binding.
//!
//! It exposes exactly what the core exposes about a hardware key: its public
//! key, a signature over a caller-supplied 32-byte digest, and the backend's
//! attestation evidence. There is no call that returns, imports or exports
//! private key material, and no constructor that accepts one: a key object
//! can only come from `DeviceKey.open`, which goes to the TPM (Linux
//! `/dev/tpmrm0`, Windows TBS) or the Apple Secure Enclave. A machine with
//! neither gets an error, never a key held in memory.

pub use tenzro_device_key_node::{
    Key, KeyAttestation, NO_HARDWARE, platform_backend, set_key_namespace,
};

#[cfg(feature = "python")]
mod python {
    use pyo3::exceptions::{PyRuntimeError, PyValueError};
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    /// `"tpm"`, `"secure-enclave"`, or `None` when this machine has neither.
    #[pyfunction]
    fn platform_backend() -> Option<&'static str> {
        super::platform_backend()
    }

    /// Place every key this process opens under the node key namespace
    /// `namespace` (a node's `hardware_key_namespace`). Set once, before any
    /// key is opened.
    #[pyfunction]
    fn set_key_namespace(namespace: &str) -> PyResult<()> {
        super::set_key_namespace(namespace).map_err(PyValueError::new_err)
    }

    /// One hardware-resident P-256 key.
    #[pyclass(frozen, module = "tenzro_device_key")]
    struct DeviceKey {
        key: super::Key,
    }

    #[pymethods]
    impl DeviceKey {
        /// Open the labelled hardware key, creating it on first use.
        #[staticmethod]
        fn open(label: &str) -> PyResult<Self> {
            super::Key::open(label)
                .map(|key| Self { key })
                .map_err(PyRuntimeError::new_err)
        }

        #[getter]
        fn backend(&self) -> &'static str {
            self.key.backend()
        }

        #[getter]
        fn label(&self) -> String {
            self.key.label()
        }

        /// Uncompressed SEC1 public key (65 bytes).
        fn public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
            let pk = self.key.public_key().map_err(PyRuntimeError::new_err)?;
            Ok(PyBytes::new(py, &pk))
        }

        /// ECDSA P-256 over a 32-byte SHA-256 digest; raw low-S `r || s`.
        fn sign_digest<'py>(
            &self,
            py: Python<'py>,
            digest: &[u8],
        ) -> PyResult<Bound<'py, PyBytes>> {
            if digest.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "expected a 32-byte digest, got {} bytes",
                    digest.len()
                )));
            }
            let digest = digest.to_vec();
            let sig = py
                .detach(|| self.key.sign_digest(&digest))
                .map_err(PyRuntimeError::new_err)?;
            Ok(PyBytes::new(py, &sig))
        }

        /// The backend's attestation evidence: `(backend, evidence, sec1_public_key)`.
        fn attest<'py>(
            &self,
            py: Python<'py>,
        ) -> PyResult<(String, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
            let a = py
                .detach(|| self.key.attest())
                .map_err(PyRuntimeError::new_err)?;
            Ok((
                a.backend,
                PyBytes::new(py, &a.evidence),
                PyBytes::new(py, &a.public_key),
            ))
        }
    }

    #[pymodule]
    fn tenzro_device_key(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(platform_backend, m)?)?;
        m.add_function(wrap_pyfunction!(set_key_namespace, m)?)?;
        m.add_class::<DeviceKey>()?;
        m.add("NO_HARDWARE", super::NO_HARDWARE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn open_without_hardware_refuses_with_no_fallback() {
        if super::platform_backend().is_none() {
            let err = super::Key::open("tenzro-py-test")
                .err()
                .expect("no hardware, no key");
            assert_eq!(err, super::NO_HARDWARE);
        }
    }

    #[test]
    fn open_refuses_an_empty_label() {
        assert!(super::Key::open("").is_err());
    }
}
