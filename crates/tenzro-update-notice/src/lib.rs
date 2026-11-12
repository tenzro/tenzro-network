//! Signed release notices: how a Tenzro node learns that a newer release exists.
//!
//! A notice is a small JSON document the release publisher signs with the
//! release key (ECDSA P-256, the key the installers embed). It carries the
//! release, a digest and size per platform archive, where the signed manifest
//! lives, plain release notes, a severity, the oldest version that stays
//! compatible, and an expiry. It carries no executable content: nothing in it
//! is ever run, and installing a release stays a separate, explicit step
//! (`tenzro update`).
//!
//! - [`notice`]: the format, signing, and the checks a node applies.
//! - [`store`]: the newest verified notice, cached on disk.
//! - [`banner`]: the one-line message, shown at most once per version per day,
//!   and the rules that hide it.
//!
//! The format is described in `docs/UPDATE-NOTICE.md`.

pub mod banner;
pub mod notice;
pub mod store;

pub use notice::{Notice, NoticeError, PlatformArchive, Policy, Severity, Version};
pub use store::{NoticeStore, Offer};
