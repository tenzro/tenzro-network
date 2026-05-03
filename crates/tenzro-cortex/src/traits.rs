//! Core Cortex traits.

use async_trait::async_trait;
use tenzro_types::cortex::{CortexModelFamily, CortexRequest, CortexResponse};

use crate::error::Result;

/// Backend trait for a recurrent-depth reasoning model.
///
/// Implementations own the actual inference path — typically this means
/// talking to an OpenMythos-style HTTP sidecar, but it could also be an
/// in-process PyTorch binding or a deterministic mock for tests.
///
/// Workers consume this trait via [`crate::worker::CortexWorker`] and
/// are agnostic to which backend is wired in.
#[async_trait]
pub trait RecurrentDepthModel: Send + Sync {
    /// Stable model identifier (matches [`tenzro_types::model::ModelInfo::model_id`]).
    fn model_id(&self) -> &str;

    /// Advertised family metadata for this model (max loops, MoE shape, attn type).
    fn family(&self) -> &CortexModelFamily;

    /// Execute a reasoning request.
    ///
    /// Implementations MUST honor `request.budget.max_loops`, SHOULD attempt
    /// to execute at least `request.budget.min_loops`, and MUST report the
    /// actual `loops_used` in the returned response metadata.
    async fn infer(&self, request: &CortexRequest) -> Result<CortexResponse>;
}
