//! Onboarding for the initial, team-operated phase of Tenzro Network.
//!
//! Applicants apply on tenzro.com/join; the Tenzro team reviews and, if it
//! approves, sends the role's stake to the applicant's wallet. This module is
//! what the CLI shows meanwhile:
//!
//! * [`foundation_config`]: the ONE file holding contact channels, join link,
//!   reply-time text, status endpoint and the default phase.
//! * [`phase`]: the switch that makes the whole message go away.
//! * [`role`]: roles and their stake minimums.
//! * [`state`]: applied > under review > approved > funded > staked > serving.
//! * [`status_source`]: the interface to the website's status endpoint.
//! * [`message`]: the single builder of the user-facing wording (join,
//!   setup, stake, validator register and doctor all use it).
//! * [`ceremony`]: the browser passkey ceremony that gives a human identity its key.
//! * [`flow`]: reading the chain and the website, gating, resuming.

pub mod ceremony;
pub mod disk;
pub mod flow;
pub mod foundation_config;
pub mod message;
pub mod phase;
pub mod role;
pub mod state;
pub mod status_source;
pub mod wizard;
