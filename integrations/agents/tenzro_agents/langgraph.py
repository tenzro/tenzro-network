"""LangGraph / LangChain adapter for Tenzro.

Integrates via LangChain's native extension point — a
``BaseCallbackHandler`` subclass — exactly the pattern the bridge doc
(Layer 4) prescribes. LangGraph executes the graph; Tenzro rides along on
the callback surface to emit a DID envelope per node, run an AP2 mandate
check on tool-call nodes, and submit ERC-8004 feedback on graph finish.

Current API (langchain-core ``BaseCallbackHandler``):
https://reference.langchain.com/python/langchain-core/callbacks/base/BaseCallbackHandler
Method signatures verified against
https://raw.githubusercontent.com/langchain-ai/langchain/master/libs/core/langchain_core/callbacks/base.py
::

    on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None,
                  tags=None, metadata=None, inputs=None, **kwargs)
    on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs)
    on_chain_end(self, outputs, *, run_id, parent_run_id=None, **kwargs)

``langchain_core`` is imported lazily so this module imports cleanly when
LangChain is not installed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .core import ReputationHook, TenzroClient, TenzroDidEnvelope


def _base_callback_handler() -> type:
    """Return ``langchain_core.callbacks.base.BaseCallbackHandler``.

    Imported lazily so ``import tenzro_agents`` works without LangChain.
    """
    try:
        from langchain_core.callbacks.base import BaseCallbackHandler
    except ImportError as exc:  # pragma: no cover - exercised when missing
        raise ImportError(
            "TenzroLangGraphCallback requires langchain-core. "
            "Install with: pip install langchain-core"
        ) from exc
    return BaseCallbackHandler


def make_langgraph_callback(
    client: TenzroClient,
    did: str,
    *,
    signing_key: Any = None,
    subject_agent_id: int | None = None,
    mandate_factory: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
):
    """Construct a ``TenzroLangGraphCallback`` instance.

    Factory function because the base class is resolved lazily — the class
    can only be defined once LangChain is importable.

    Parameters
    ----------
    client:
        Configured :class:`~tenzro_agents.core.TenzroClient`.
    did:
        This agent's TDIP DID, signed into every node envelope.
    signing_key:
        Optional ``nacl.signing.SigningKey`` for envelope signing. If
        ``None``, the client's ``signing_key`` is used.
    subject_agent_id:
        ERC-8004 agent id for reputation feedback on graph finish.
    mandate_factory:
        Optional ``callable(tool_inputs) -> (checkout, payment)`` returning
        a mandate pair to validate before a tool-call node runs.
    """
    BaseCallbackHandler = _base_callback_handler()

    class TenzroLangGraphCallback(BaseCallbackHandler):
        """Emits Tenzro identity / mandate / reputation on graph events."""

        def __init__(self) -> None:
            super().__init__()
            self.client = client
            self.did = did
            self.signing_key = signing_key or client.signing_key
            self.subject_agent_id = subject_agent_id
            self.mandate_factory = mandate_factory
            self.last_envelope: TenzroDidEnvelope | None = None

        # -- identity envelope per node ---------------------------------
        def on_tool_start(
            self,
            serialized: dict[str, Any],
            input_str: str,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            tags: Any = None,
            metadata: Any = None,
            inputs: Any = None,
            **kwargs: Any,
        ) -> Any:
            tool_name = (serialized or {}).get("name", "tool")
            params = {"tool": tool_name, "input": input_str, "run_id": str(run_id)}
            if self.signing_key is not None:
                self.last_envelope = TenzroDidEnvelope.sign(
                    self.signing_key, self.did, f"langgraph.tool.{tool_name}", params
                )
            # AP2 mandate check on tool-call nodes.
            if self.mandate_factory is not None:
                checkout, payment = self.mandate_factory(inputs or {"input": input_str})
                self.client.validate_mandate_pair(checkout, payment)

        def on_tool_end(
            self,
            output: Any,
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> Any:
            # Hook point for per-tool receipts; the graph-finish hook owns
            # reputation submission.
            return None

        # -- reputation on graph finish ---------------------------------
        def on_chain_end(
            self,
            outputs: dict[str, Any],
            *,
            run_id: Any,
            parent_run_id: Any = None,
            **kwargs: Any,
        ) -> Any:
            # Only the top-level chain (no parent) marks graph completion.
            if parent_run_id is None and self.subject_agent_id is not None:
                ReputationHook(self.client, self.subject_agent_id).on_finish(
                    "success", context_uri=str(run_id)
                )

    return TenzroLangGraphCallback()


__all__ = ["make_langgraph_callback"]
