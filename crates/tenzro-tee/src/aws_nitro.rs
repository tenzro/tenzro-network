//! AWS Nitro Enclaves evidence generation.
//!
//! Inside an enclave this provider asks the Nitro Secure Module (`/dev/nsm`)
//! for an attestation document: a COSE_Sign1 over the enclave's PCRs, a
//! certificate chain to the AWS Nitro root, a timestamp and the caller's
//! `user_data`. The document is self-contained, so verification
//! ([`crate::verify::nitro`]) needs no network access.
//!
//! There is no simulated mode. A host without `/dev/nsm` reports itself
//! unavailable, and every evidence-producing call fails.

use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;
use tenzro_types::tee::*;

#[derive(Clone)]
enum DocumentSource {
    Hardware,
    /// Tests only: a CBOR map shaped like a document but unsigned, which no
    /// verifier accepts.
    #[cfg(test)]
    Unsigned,
}

/// AWS Nitro Enclaves provider.
#[derive(Clone)]
pub struct AwsNitroProvider {
    available: bool,
    source: DocumentSource,
}

impl std::fmt::Debug for AwsNitroProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsNitroProvider")
            .field("available", &self.available)
            .finish_non_exhaustive()
    }
}

/// Encode an NSM `Attestation` request.
fn nsm_request(user_data: &[u8]) -> Result<Vec<u8>> {
    use ciborium::value::Value;
    let req = Value::Map(vec![(
        Value::Text("Attestation".into()),
        Value::Map(vec![
            (
                Value::Text("user_data".into()),
                Value::Bytes(user_data.to_vec()),
            ),
            (Value::Text("nonce".into()), Value::Null),
            (Value::Text("public_key".into()), Value::Null),
        ]),
    )]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&req, &mut out)
        .map_err(|e| TeeError::AttestationGenerationFailed(format!("NSM request: {e}")))?;
    Ok(out)
}

/// Extract the document from an NSM `Attestation` response.
fn nsm_document(response: &[u8]) -> Result<Vec<u8>> {
    use ciborium::value::Value;
    let bad = |m: &str| TeeError::AttestationGenerationFailed(format!("NSM response: {m}"));
    let v: Value = ciborium::de::from_reader(response).map_err(|e| bad(&e.to_string()))?;
    let Value::Map(outer) = v else {
        return Err(bad("not a map"));
    };
    for (k, v) in outer {
        match (k, v) {
            (Value::Text(k), Value::Map(inner)) if k == "Attestation" => {
                for (k, v) in inner {
                    if let (Value::Text(k), Value::Bytes(doc)) = (k, v)
                        && k == "document"
                    {
                        return Ok(doc);
                    }
                }
            }
            (Value::Text(k), v) if k == "Error" => return Err(bad(&format!("{v:?}"))),
            _ => {}
        }
    }
    Err(bad("no attestation document"))
}

impl AwsNitroProvider {
    /// A provider for this enclave's NSM, if any.
    pub fn new() -> Self {
        Self {
            available: std::path::Path::new("/dev/nsm").exists(),
            source: DocumentSource::Hardware,
        }
    }

    #[cfg(test)]
    fn unsigned_for_tests() -> Self {
        Self {
            available: true,
            source: DocumentSource::Unsigned,
        }
    }

    /// One NSM request/response through `NSM_IOCTL_REQUEST`.
    fn nsm_call(request: &[u8]) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/nsm")
                .map_err(|e| {
                    TeeError::AttestationGenerationFailed(format!("open /dev/nsm: {e}"))
                })?;
            let mut response = vec![0u8; 16 * 1024];
            // struct nsm_message { struct iovec request; struct iovec response; }
            #[repr(C)]
            struct Message {
                req_base: *const u8,
                req_len: usize,
                resp_base: *mut u8,
                resp_len: usize,
            }
            let mut msg = Message {
                req_base: request.as_ptr(),
                req_len: request.len(),
                resp_base: response.as_mut_ptr(),
                resp_len: response.len(),
            };
            let size = std::mem::size_of::<Message>() as u32;
            let nr = (3u32 << 30) | (size << 16) | (0x0Au32 << 8);
            // SAFETY: `msg` points at `request` and `response`, both alive for
            // the call; the driver writes at most `resp_len` bytes and updates
            // `resp_len` to the length written.
            let ret = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    nr as libc::c_ulong,
                    &mut msg as *mut Message,
                )
            };
            if ret != 0 {
                return Err(TeeError::AttestationGenerationFailed(format!(
                    "NSM request failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            response.truncate(msg.resp_len);
            Ok(response)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(TeeError::not_available("AWS Nitro Enclaves require Linux"))
        }
    }
}

impl Default for AwsNitroProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeeProvider for AwsNitroProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::AwsNitro
    }

    async fn is_available(&self) -> Result<bool> {
        Ok(self.available)
    }

    /// `user_data` is carried verbatim as the document's `user_data`.
    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }
        let attestation_data = match self.source {
            DocumentSource::Hardware => nsm_document(&Self::nsm_call(&nsm_request(user_data)?)?)?,
            #[cfg(test)]
            DocumentSource::Unsigned => nsm_request(user_data)?,
        };
        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::AwsNitro,
            user_data: user_data.to_vec(),
            attestation_data,
            timestamp: tenzro_types::Timestamp::now(),
            metadata: HashMap::new(),
            ..Default::default()
        })
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }
        let data = request.params;
        let attestation = if request.include_attestation {
            let binding =
                crate::traits::enclave_response_binding(&request.id, &request.operation, &data);
            Some(self.generate_attestation(&binding).await?)
        } else {
            None
        };
        Ok(EnclaveResponse {
            request_id: request.id,
            success: true,
            data,
            error: None,
            attestation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsm_messages_round_trip() {
        use ciborium::value::Value;
        let req = nsm_request(b"ud").unwrap();
        let v: Value = ciborium::de::from_reader(req.as_slice()).unwrap();
        assert!(matches!(v, Value::Map(_)));
        let resp = Value::Map(vec![(
            Value::Text("Attestation".into()),
            Value::Map(vec![(
                Value::Text("document".into()),
                Value::Bytes(vec![1, 2, 3]),
            )]),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&resp, &mut bytes).unwrap();
        assert_eq!(nsm_document(&bytes).unwrap(), vec![1, 2, 3]);
        let err = Value::Map(vec![(
            Value::Text("Error".into()),
            Value::Text("InvalidArgument".into()),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&err, &mut bytes).unwrap();
        assert!(nsm_document(&bytes).is_err());
    }

    #[tokio::test]
    async fn an_unsigned_document_never_verifies() {
        let provider = AwsNitroProvider::unsigned_for_tests();
        let report = provider.generate_attestation(b"challenge").await.unwrap();
        let policy = crate::verify::VerifyPolicy::now(b"challenge".to_vec());
        assert!(crate::verify::verify_report(&report, &policy).is_err());
    }

    #[tokio::test]
    async fn off_hardware_nothing_is_produced() {
        let provider = AwsNitroProvider::new();
        if provider.is_available().await.unwrap() {
            return;
        }
        assert!(provider.generate_attestation(b"x").await.is_err());
    }
}
