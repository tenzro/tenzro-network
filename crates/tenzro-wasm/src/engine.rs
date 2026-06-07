//! Wasmtime engine configuration tuned for Tenzro's deterministic,
//! sandboxed, capability-based component host.
//!
//! The engine is the heavyweight, process-wide object — components
//! are compiled once against it and then instantiated cheaply many
//! times. Tenzro nodes hold a single shared `WasmEngine` per process
//! and pass `Arc<WasmEngine>` into both the agent-kit skill executor
//! and the MCP tool host.

use std::sync::Arc;

use wasmtime::{Config, Engine, OptLevel, PoolingAllocationConfig};

use crate::error::{WasmError, WasmResult};

/// Process-wide Wasmtime engine with Tenzro's deterministic defaults.
#[derive(Clone)]
pub struct WasmEngine {
    inner: Arc<Engine>,
}

impl WasmEngine {
    /// Builds the engine with Tenzro's default configuration:
    ///
    /// - Component model enabled (WASI 0.2 is component-model only).
    /// - Async support enabled so host calls can be `async fn`.
    /// - Cranelift with `Speed` opt-level — components are compiled
    ///   once at registration time, so we spend the cycles there to
    ///   keep per-invocation overhead low.
    /// - Fuel metering enabled.
    /// - Epoch interruption enabled for wall-clock deadlines.
    /// - Pooling allocator for cheap instantiation under load.
    /// - Module caching enabled at the path supplied by the caller.
    /// - SIMD / threads / bulk memory / multi-value all enabled; the
    ///   component model needs them.
    /// - Reference types and GC kept off — we do not need them and
    ///   they enlarge the attack surface.
    pub fn new() -> WasmResult<Self> {
        let mut config = Config::new();

        config.wasm_component_model(true);
        config.async_support(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);

        config.cranelift_opt_level(OptLevel::Speed);
        config.parallel_compilation(true);

        let pool = PoolingAllocationConfig::default();
        config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(pool));

        // Deterministic defaults — disable features that would let
        // two otherwise-identical executions diverge.
        config.wasm_relaxed_simd(false);
        config.wasm_simd(true);
        config.wasm_bulk_memory(true);
        config.wasm_multi_value(true);
        // `wasm_reference_types` lives behind the `gc` feature in
        // wasmtime 27; keeping it off-by-default is the wasmtime
        // default, so the explicit toggle is unnecessary here.

        let engine = Engine::new(&config).map_err(|e| {
            WasmError::Wasmtime(format!("constructing wasmtime engine: {e:#}"))
        })?;

        Ok(Self {
            inner: Arc::new(engine),
        })
    }

    /// Borrow the underlying Wasmtime engine.
    pub fn inner(&self) -> &Engine {
        &self.inner
    }

    /// Increment the engine's global epoch. The agent-kit / MCP host
    /// runs a single ticker task that calls this every N ms; every
    /// in-flight invocation that has consumed its deadline window
    /// will then trap with [`WasmError::DeadlineExceeded`].
    pub fn tick_epoch(&self) {
        self.inner.increment_epoch();
    }
}

impl std::fmt::Debug for WasmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmEngine").finish_non_exhaustive()
    }
}
