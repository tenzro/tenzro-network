//! OCI base-image pull + layer unpack (feature `oci`).
//!
//! v1 pulls a base **only by pinned digest** from a trusted registry and
//! unpacks its layers into a directory that [`crate::stage`] overlays. It does
//! **not** execute any image entrypoint or `RUN` step — the base is treated as
//! an inert tarball of files. (v2's untrusted `RUN` steps must run inside a
//! throwaway build-VM, out of scope here.)

use std::path::Path;

use oci_client::{Client, Reference, client::ClientConfig, secrets::RegistryAuth};

use crate::error::BuildError;
use crate::spec::OciRef;

/// Media types we accept as layers.
const LAYER_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

/// Pull `img` by digest and unpack its layers (in order) into `dest`. Returns
/// the resolved manifest digest actually fetched (must equal the pinned one).
pub async fn pull_and_unpack(img: &OciRef, dest: &Path) -> Result<String, BuildError> {
    img.validate().map_err(BuildError::Invalid)?;
    let reference: Reference = img
        .reference()
        .parse()
        .map_err(|e| BuildError::Oci(format!("bad reference {}: {e}", img.reference())))?;

    let client = Client::new(ClientConfig::default());
    let auth = RegistryAuth::Anonymous;

    let accepted: Vec<&str> = LAYER_MEDIA_TYPES.to_vec();
    let image = client
        .pull(&reference, &auth, accepted)
        .await
        .map_err(|e| BuildError::Oci(format!("pull {}: {e}", img.reference())))?;

    // Enforce the pin: the digest we asked for is what we got.
    if let Some(got) = image.digest.as_deref()
        && got != img.digest
    {
        return Err(BuildError::Oci(format!(
            "digest mismatch: pinned {} but registry returned {got}",
            img.digest
        )));
    }

    std::fs::create_dir_all(dest)
        .map_err(|e| BuildError::Oci(format!("mkdir {}: {e}", dest.display())))?;

    for layer in &image.layers {
        let gz =
            layer.media_type.ends_with("gzip") || layer.media_type.ends_with("tar+gzip");
        crate::archive::unpack_tar(&layer.data, gz, dest)?;
    }
    Ok(image.digest.unwrap_or_else(|| img.digest.clone()))
}
