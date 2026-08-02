"""Microsoft Agent Framework adapter for Tenzro.

Integrates via the Agent Framework middleware pipeline (bridge doc
Layer 4): an ``AgentMiddleware`` subclass whose ``process`` method runs a
DID envelope + AP2 mandate check before the agent executes, and submits
ERC-8004 feedback after. A companion ``FunctionMiddleware`` runs the
mandate check at tool-call granularity.

Current API (microsoft/agent-framework Python middleware):
https://learn.microsoft.com/en-us/agent-framework/agents/middleware/ ::

    from agent_framework import AgentMiddleware, FunctionMiddleware
    from agent_framework import AgentContext, FunctionInvocationContext

    class MyMiddleware(AgentMiddleware):
        async def process(self, context: AgentContext,
                          call_next: Callable[[], Awaitable[None]]) -> None:
            ...
            await call_next()

Middleware is registered on the agent:
``Agent(..., middleware=[TenzroAgentFrameworkMiddleware(...)])``. The base
classes are imported lazily so this module imports without the framework.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from .core import ReputationHook, TenzroClient, TenzroDidEnvelope


def _agent_middleware_base() -> type:
    try:
        from agent_framework import AgentMiddleware
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "TenzroAgentFrameworkMiddleware requires agent-framework. "
            "Install with: pip install agent-framework"
        ) from exc
    return AgentMiddleware


def _function_middleware_base() -> type:
    try:
        from agent_framework import FunctionMiddleware
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "TenzroFunctionMiddleware requires agent-framework. "
            "Install with: pip install agent-framework"
        ) from exc
    return FunctionMiddleware


def make_agent_framework_middleware(
    client: TenzroClient,
    did: str,
    *,
    signing_key: Any = None,
    subject_agent_id: int | None = None,
    mandate_factory: Callable[[Any], tuple[Mapping[str, Any], Mapping[str, Any]]] | None = None,
) -> Any:
    """Construct a ``TenzroAgentFrameworkMiddleware`` instance.

    Factory because ``AgentMiddleware`` is resolved lazily. Add to an agent
    via ``Agent(..., middleware=[make_agent_framework_middleware(client, did)])``.
    """
    AgentMiddleware = _agent_middleware_base()

    class TenzroAgentFrameworkMiddleware(AgentMiddleware):
        """Wraps an agent run with Tenzro identity / mandate / reputation."""

        async def process(
            self,
            context: Any,
            call_next: Callable[[], Awaitable[None]],
        ) -> None:
            # DID envelope over the inbound run.
            agent_name = getattr(getattr(context, "agent", None), "name", "agent")
            if signing_key is not None or client.signing_key is not None:
                TenzroDidEnvelope.sign(
                    signing_key or client.signing_key,
                    did,
                    f"agentframework.run.{agent_name}",
                    {"agent": agent_name},
                )
            # AP2 mandate validation before the run.
            if mandate_factory is not None:
                checkout, payment = mandate_factory(context)
                client.validate_mandate_pair(checkout, payment)

            outcome = "success"
            try:
                await call_next()
            except Exception:
                outcome = "failure"
                raise
            finally:
                if subject_agent_id is not None:
                    ReputationHook(client, subject_agent_id).on_finish(outcome)

    return TenzroAgentFrameworkMiddleware()


def make_function_middleware(
    client: TenzroClient,
    *,
    mandate_factory: Callable[[Any], tuple[Mapping[str, Any], Mapping[str, Any]]] | None = None,
) -> Any:
    """Construct a ``FunctionMiddleware`` that validates mandates per tool call."""
    FunctionMiddleware = _function_middleware_base()

    class TenzroFunctionMiddleware(FunctionMiddleware):
        async def process(
            self,
            context: Any,
            call_next: Callable[[], Awaitable[None]],
        ) -> None:
            if mandate_factory is not None:
                checkout, payment = mandate_factory(context)
                client.validate_mandate_pair(checkout, payment)
            await call_next()

    return TenzroFunctionMiddleware()


__all__ = ["make_agent_framework_middleware", "make_function_middleware"]
