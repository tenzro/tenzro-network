"""OpenAI Agents SDK adapter for Tenzro.

Integrates via the OpenAI Agents SDK ``RunHooks`` surface (bridge doc
Layer 4): the wrapper installs a DID emitter + AP2 validator + ERC-8004
dispatcher across the entire ``Runner.run(...)`` invocation.

Current API (openai-agents-python ``RunHooks`` / ``RunHooksBase``):
https://openai.github.io/openai-agents-python/ref/lifecycle/
::

    class RunHooks:  # RunHooksBase[TContext, Agent]
        async def on_agent_start(self, context, agent) -> None
        async def on_agent_end(self, context, agent, output) -> None
        async def on_tool_start(self, context, agent, tool) -> None
        async def on_tool_end(self, context, agent, tool, result) -> None
        async def on_handoff(self, context, from_agent, to_agent) -> None

Hooks are passed to ``Runner.run(agent, ..., hooks=...)``. ``RunHooks`` is
imported lazily so this module imports without the SDK installed.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Tuple

from .core import ReputationHook, TenzroClient, TenzroDidEnvelope


def _run_hooks_base() -> type:
    try:
        from agents import RunHooks
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "TenzroOpenAIWrapper requires openai-agents. "
            "Install with: pip install openai-agents"
        ) from exc
    return RunHooks


class TenzroOpenAIWrapper:
    """Builds Tenzro ``RunHooks`` for the OpenAI Agents SDK.

    Construct once with a configured :class:`~tenzro_agents.core.TenzroClient`
    and the agent's DID, then pass ``wrapper.run_hooks()`` to
    ``Runner.run(agent, input, hooks=...)``.
    """

    def __init__(
        self,
        client: TenzroClient,
        did: str,
        *,
        signing_key: Any = None,
        subject_agent_id: Optional[int] = None,
        mandate_factory: Optional[Callable[[Any], Tuple[Mapping[str, Any], Mapping[str, Any]]]] = None,
    ) -> None:
        self.client = client
        self.did = did
        self.signing_key = signing_key or client.signing_key
        self.subject_agent_id = subject_agent_id
        self.mandate_factory = mandate_factory

    def run_hooks(self) -> Any:
        """Return a ``RunHooks`` instance wiring Tenzro into the run."""
        RunHooks = _run_hooks_base()
        wrapper = self

        class _TenzroRunHooks(RunHooks):
            async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
                # DID envelope per tool invocation.
                tool_name = getattr(tool, "name", str(tool))
                params = {"tool": tool_name, "agent": getattr(agent, "name", "")}
                if wrapper.signing_key is not None:
                    TenzroDidEnvelope.sign(
                        wrapper.signing_key, wrapper.did,
                        f"openai.tool.{tool_name}", params,
                    )
                # AP2 mandate validation on tool calls.
                if wrapper.mandate_factory is not None:
                    checkout, payment = wrapper.mandate_factory(tool)
                    wrapper.client.validate_mandate_pair(checkout, payment)

            async def on_tool_end(
                self, context: Any, agent: Any, tool: Any, result: Any
            ) -> None:
                return None

            async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
                # ERC-8004 dispatch at end of the run.
                if wrapper.subject_agent_id is not None:
                    ReputationHook(
                        wrapper.client, wrapper.subject_agent_id
                    ).on_finish("success")

        return _TenzroRunHooks()


__all__ = ["TenzroOpenAIWrapper"]
