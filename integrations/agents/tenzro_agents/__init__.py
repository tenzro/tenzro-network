"""tenzro-agents — cross-framework Tenzro coordination shims.

One shared core (:mod:`tenzro_agents.core`) plus thin per-framework
adapters (LangGraph, CrewAI, Letta, OpenAI Agents SDK, Google ADK,
Microsoft Agent Framework). See
``docs/architecture/agent-interop-protocol-bridge.md`` (Layer 4, Open
Question #4): one integration core, six thin adapters — not six codebases.

Importing this package never requires any agent framework to be installed.
The core is always available; framework adapters import their framework
lazily and raise a clear ``ImportError`` only when actually invoked. To
keep ``import tenzro_agents`` clean even if a framework's own import side
effects fail, the adapter submodules are NOT eagerly imported here.
"""

from __future__ import annotations

from .core import (
    DOMAIN_TAG,
    ReputationHook,
    TenzroClient,
    TenzroDidEnvelope,
    TenzroRpcError,
    canonical_params_hash,
    canonical_preimage,
    cart_item,
    checkout_hash,
    checkout_mandate,
    payment_mandate,
)

__version__ = "0.1.0"

__all__ = [
    # core
    "DOMAIN_TAG",
    "ReputationHook",
    "TenzroClient",
    "TenzroDidEnvelope",
    "TenzroRpcError",
    "__version__",
    "canonical_params_hash",
    "canonical_preimage",
    # AP2 mandate helpers
    "cart_item",
    "checkout_hash",
    "checkout_mandate",
    "payment_mandate",
]
