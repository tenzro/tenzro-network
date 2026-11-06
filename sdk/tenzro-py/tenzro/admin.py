"""The node's administrative audit log: every operator call, sign-in and
completion, hash-chained and checkpointed under the node's identity key.

Both methods are operator only: the node's access policy admits the operator
DID or a policy admin.
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict, Union

from .rpc import RpcClient

Time = Union[str, int]
"""RFC 3339 text, or Unix milliseconds."""


class AuditLine(TypedDict):
    """One line of the log: the record and its SHA-256 chain hash (hex).

    ``record`` holds ``seq``, ``prev``, ``at`` (RFC 3339 UTC), ``node`` (the
    machine DID or ``None``), ``chain_id`` and ``entry``, an object
    ``{"kind": ..., "data": ...}`` whose kind is ``call``, ``completion``,
    ``sign_in``, ``checkpoint`` or ``opened``.
    """

    record: dict[str, Any]
    hash: str


class AuditPage(TypedDict):
    """``tenzro_listAdminAudit``: the selected records, oldest first."""

    count: int
    records: list[AuditLine]


class AuditVerification(TypedDict):
    """``tenzro_verifyAdminAudit``: whether the chain is whole, every
    checkpoint verifies under this node's identity key, and the log ends where
    the node last wrote; ``problems`` names everything that is wrong."""

    ok: bool
    records: int
    segments: list[str]
    first_seq: Optional[int]
    last_seq: Optional[int]
    head_hash: Optional[str]
    checkpoints: int
    signed_checkpoints: int
    unsigned_checkpoints: int
    problems: list[str]


def audit_filter(
    *,
    method: Optional[str] = None,
    principal: Optional[str] = None,
    since: Optional[Time] = None,
    until: Optional[Time] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """The ``tenzro_listAdminAudit`` params: only the fields given."""
    if limit is not None and not 1 <= limit <= 1000:
        raise ValueError("limit is 1 to 1000")
    fields = {"method": method, "principal": principal, "since": since, "until": until, "limit": limit}
    return {k: v for k, v in fields.items() if v is not None}


def audit_log(
    rpc: RpcClient,
    *,
    method: Optional[str] = None,
    principal: Optional[str] = None,
    since: Optional[Time] = None,
    until: Optional[Time] = None,
    limit: Optional[int] = None,
) -> AuditPage:
    """The most recent audit records the filter selects (default 100, at most
    1000), oldest first: about one ``method``, by one ``principal`` DID, at or
    after ``since`` and before ``until``."""
    params = audit_filter(method=method, principal=principal, since=since, until=until, limit=limit)
    return rpc.call("tenzro_listAdminAudit", params)


def verify_audit_log(rpc: RpcClient) -> AuditVerification:
    """Check the audit log's chain and its signed checkpoints."""
    return rpc.call("tenzro_verifyAdminAudit", {})


__all__ = [
    "AuditLine",
    "AuditPage",
    "AuditVerification",
    "Time",
    "audit_filter",
    "audit_log",
    "verify_audit_log",
]
