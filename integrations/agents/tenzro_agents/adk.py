"""Google ADK adapter for Tenzro.

Integrates via the Google ADK plugin system (bridge doc Layer 4): a
``BasePlugin`` subclass registered once on the ``Runner`` whose callbacks
apply globally to every agent, tool, and model call. The plugin emits a
DID envelope + AP2 mandate check before each tool call and submits ERC-8004
feedback after the run.

Current API (google-adk ``BasePlugin``), verified against
https://raw.githubusercontent.com/google/adk-python/main/src/google/adk/plugins/base_plugin.py
and https://google.github.io/adk-docs/plugins/ ::

    class BasePlugin:
        def __init__(self, name: str): ...
        async def before_tool_callback(self, *, tool, tool_args, tool_context) -> Optional[dict]
        async def after_tool_callback(self, *, tool, tool_args, tool_context, result) -> Optional[dict]
        async def after_run_callback(self, *, invocation_context) -> None

Plugins are registered on the Runner: ``Runner(..., plugins=[plugin])``.
``BasePlugin`` is imported lazily so this module imports without ADK.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .core import ReputationHook, TenzroClient, TenzroDidEnvelope


def _base_plugin() -> type:
    try:
        from google.adk.plugins.base_plugin import BasePlugin
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "tenzro_adk_plugin requires google-adk. "
            "Install with: pip install google-adk"
        ) from exc
    return BasePlugin


def tenzro_adk_plugin(
    client: TenzroClient,
    did: str,
    *,
    name: str = "tenzro",
    signing_key: Any = None,
    subject_agent_id: int | None = None,
    mandate_factory: Callable[[Any, Mapping[str, Any]], tuple[Mapping[str, Any], Mapping[str, Any]]] | None = None,
) -> Any:
    """Construct a Tenzro ADK plugin to register on a ``Runner``.

    Factory because ``BasePlugin`` is resolved lazily. Register with
    ``Runner(agent=..., plugins=[tenzro_adk_plugin(client, did)])``.
    """
    BasePlugin = _base_plugin()

    class _TenzroAdkPlugin(BasePlugin):
        def __init__(self) -> None:
            super().__init__(name=name)
            self.client = client
            self.did = did
            self.signing_key = signing_key or client.signing_key
            self.subject_agent_id = subject_agent_id
            self.mandate_factory = mandate_factory

        async def before_tool_callback(
            self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any
        ) -> dict | None:
            tool_name = getattr(tool, "name", str(tool))
            params = {"tool": tool_name, "args": tool_args}
            if self.signing_key is not None:
                TenzroDidEnvelope.sign(
                    self.signing_key, self.did, f"adk.tool.{tool_name}", params
                )
            if self.mandate_factory is not None:
                checkout, payment = self.mandate_factory(tool, tool_args)
                self.client.validate_mandate_pair(checkout, payment)
            return None  # observe-only: let the tool proceed.

        async def after_tool_callback(
            self,
            *,
            tool: Any,
            tool_args: dict[str, Any],
            tool_context: Any,
            result: dict,
        ) -> dict | None:
            return None

        async def after_run_callback(self, *, invocation_context: Any) -> None:
            if self.subject_agent_id is not None:
                ReputationHook(self.client, self.subject_agent_id).on_finish(
                    "success"
                )

    return _TenzroAdkPlugin()


__all__ = ["tenzro_adk_plugin"]
