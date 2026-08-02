"""Letta adapter for Tenzro.

Integrates via Letta's native extension point (bridge doc Layer 4): tool
registration. Three Tenzro-backed tools are exposed as plain Python
functions and registered with a Letta client via
``client.tools.upsert_from_function(func=...)``:

* ``tenzro_memory_grant`` — record a DID-scoped memory-access grant
  (emits a Tenzro task so the grant is auditable cross-platform).
* ``tenzro_memory_recall`` — recall previously-archived memory by key.
* ``tenzro_memory_archive`` — archive a memory blob; the archive hook
  submits ERC-8004 feedback recording the archival event.

Current API (Letta Python SDK / ``letta-client``):
https://docs.letta.com/guides/agents/custom-tools — tools are registered
with ``client.tools.upsert_from_function(func=your_function)`` and the
client is ``from letta_client import Letta``. Archival memory is the agent's
out-of-context searchable store accessed through tool calls.

The Letta client is imported lazily; the three tool functions themselves
have no Letta import dependency (they only touch the Tenzro client), so
they remain callable in tests without Letta installed.
"""

from __future__ import annotations

from typing import Any

from .core import ReputationHook, TenzroClient

# Module-level handle the registered tools close over. Set by
# ``install_tenzro_memory_tools``; kept module-scoped so the tool
# functions registered with Letta carry a clean top-level signature.
_CLIENT: TenzroClient | None = None
_DID: str | None = None
_SUBJECT_AGENT_ID: int | None = None


def tenzro_memory_grant(grantee_did: str, scope: str) -> dict[str, Any]:
    """Grant ``grantee_did`` access to this agent's memory under ``scope``.

    Records the grant as a Tenzro task so the authorisation is auditable
    across frameworks (bridge doc: portable authz). Returns the posted
    task record.

    Args:
        grantee_did: TDIP DID being granted memory access.
        scope: Free-form scope label (e.g. "recall:project-x").
    """
    if _CLIENT is None:
        raise RuntimeError("Tenzro memory tools not installed")
    return _CLIENT.post_task(
        {
            "kind": "memory_grant",
            "owner_did": _DID,
            "grantee_did": grantee_did,
            "scope": scope,
        }
    )


def tenzro_memory_recall(key: str) -> dict[str, Any]:
    """Recall an archived memory entry by ``key``.

    Args:
        key: The archive key returned by :func:`tenzro_memory_archive`.
    """
    if _CLIENT is None:
        raise RuntimeError("Tenzro memory tools not installed")
    return _CLIENT.call("tenzro_getTask", {"task_id": key})


def tenzro_memory_archive(content: str, label: str = "memory") -> dict[str, Any]:
    """Archive ``content`` to the agent's durable store.

    Posts a Tenzro task carrying the archived blob, then (the archive hook)
    submits ERC-8004 feedback recording the archival event so the agent's
    memory-stewardship shows up in its cross-platform reputation.

    Args:
        content: The memory blob to archive.
        label: Human label for the archive entry.
    """
    if _CLIENT is None:
        raise RuntimeError("Tenzro memory tools not installed")
    result = _CLIENT.post_task(
        {
            "kind": "memory_archive",
            "owner_did": _DID,
            "label": label,
            "content": content,
        }
    )
    # Memory-archive hook -> reputation.
    if _SUBJECT_AGENT_ID is not None:
        ReputationHook(_CLIENT, _SUBJECT_AGENT_ID).on_finish(
            "success", context_uri=f"memory:{label}"
        )
    return result


def install_tenzro_memory_tools(
    letta_client: Any,
    tenzro_client: TenzroClient,
    did: str,
    *,
    subject_agent_id: int | None = None,
) -> list[Any]:
    """Register the three Tenzro memory tools with a Letta client.

    Wires module state for the tool closures, then registers each tool via
    ``letta_client.tools.upsert_from_function(func=...)`` (the current Letta
    tool-registration API). Returns the list of registered ``Tool`` objects.
    """
    global _CLIENT, _DID, _SUBJECT_AGENT_ID
    _CLIENT = tenzro_client
    _DID = did
    _SUBJECT_AGENT_ID = subject_agent_id

    tools = []
    for func in (tenzro_memory_grant, tenzro_memory_recall, tenzro_memory_archive):
        tools.append(letta_client.tools.upsert_from_function(func=func))
    return tools


__all__ = [
    "install_tenzro_memory_tools",
    "tenzro_memory_archive",
    "tenzro_memory_grant",
    "tenzro_memory_recall",
]
