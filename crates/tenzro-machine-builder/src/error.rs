//! Builder error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("staging: {0}")]
    Stage(String),
    #[error("staged content exceeds the {0}-byte cap")]
    TooLarge(u64),
    #[error("ext4: {0}")]
    Ext4(String),
    #[error("required e2fsprogs tool `{0}` not found on PATH")]
    MissingTool(String),
    #[error("oci: {0}")]
    Oci(String),
    #[error("invalid build context: {0}")]
    Invalid(String),
}
