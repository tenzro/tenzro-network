//! tar(.gz) unpacking (feature `archive`).
//!
//! Shared by the OCI layer path and the node's app-context delivery (the built
//! app is shipped to the builder as a tar archive). Guards against path
//! traversal and honors OCI whiteout markers.

use std::path::Path;

use crate::error::BuildError;

/// Unpack a `.tar` or `.tar.gz` byte buffer into `dest`. `gzip` selects gzip
/// decompression. Applies the traversal guard and OCI whiteout handling so it is
/// safe for untrusted-layout (but trusted-source) archives.
pub fn unpack_tar(data: &[u8], gzip: bool, dest: &Path) -> Result<(), BuildError> {
    let reader: Box<dyn std::io::Read> = if gzip {
        Box::new(flate2::read::GzDecoder::new(data))
    } else {
        Box::new(std::io::Cursor::new(data))
    };
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    std::fs::create_dir_all(dest)
        .map_err(|e| BuildError::Stage(format!("mkdir {}: {e}", dest.display())))?;

    for entry in archive
        .entries()
        .map_err(|e| BuildError::Stage(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| BuildError::Stage(format!("tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| BuildError::Stage(format!("tar path: {e}")))?
            .into_owned();

        // Reject absolute / `..` components.
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        }) {
            return Err(BuildError::Stage(format!(
                "archive entry escapes root: {}",
                path.display()
            )));
        }

        // OCI whiteout markers.
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && let Some(stripped) = name.strip_prefix(".wh.")
        {
            let parent = dest.join(path.parent().unwrap_or(Path::new("")));
            let target = if stripped == ".wh..opq" {
                parent
            } else {
                parent.join(stripped)
            };
            let _ = std::fs::remove_dir_all(&target);
            let _ = std::fs::remove_file(&target);
            continue;
        }

        entry
            .unpack_in(dest)
            .map_err(|e| BuildError::Stage(format!("unpack {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_a_plain_tar() {
        // Build a tiny tar in memory.
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let data = b"hello";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            b.append_data(&mut header, "app/index.js", &data[..]).unwrap();
            b.finish().unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        unpack_tar(&buf, false, tmp.path()).unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("app/index.js")).unwrap(),
            b"hello"
        );
    }

    fn tar_with(path: &str, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut b = tar::Builder::new(&mut buf);
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        b.append_data(&mut header, path, data).unwrap();
        b.finish().unwrap();
        drop(b);
        buf
    }

    #[test]
    fn whiteout_marker_removes_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        // Lower layer creates the file.
        unpack_tar(&tar_with("data/keep.txt", b"a"), false, tmp.path()).unwrap();
        unpack_tar(&tar_with("data/gone.txt", b"b"), false, tmp.path()).unwrap();
        assert!(tmp.path().join("data/gone.txt").is_file());
        // Upper layer whites it out.
        unpack_tar(&tar_with("data/.wh.gone.txt", b""), false, tmp.path()).unwrap();
        assert!(!tmp.path().join("data/gone.txt").exists(), "whiteout removed it");
        assert!(tmp.path().join("data/keep.txt").is_file(), "sibling kept");
    }
}
