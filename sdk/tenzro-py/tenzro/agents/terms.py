"""Delegated agents: Terms, and actions within them.

An agent has exactly one root (a human passkey or a machine TPM/Secure Enclave
key); its authority is only its consensus Terms, granted by that root. The
root approves Terms (and every change to them, and revocation) through a
custody challenge on its smart account, answered by ``authorize`` with an
assertion of a passkey enrolled there. Inside its Terms the agent acts with
its access token through a serving node (:func:`agent_act`), which signs with
its hardware key only within the Terms in chain state; the VM checks them
again at execution.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypedDict

from ..rpc import RpcClient
from ..typed_tx import TypedTransaction, TypedTxClient
from ..wallet import HybridSigner


class ServingNodeRef(TypedDict, total=False):
    """A serving node assigned to a delegated agent."""

    machine_did: str
    operator_did: str
    #: Thumbprint of the node's key for this agent.
    dpop_jkt: str


class CounterpartyKyc(TypedDict):
    min_tier: int
    registry: str


class DelegationScope(TypedDict, total=False):
    #: Wei, canonical decimal.
    max_transaction_value: str
    #: Wei, canonical decimal.
    max_daily_spend: str
    allowed_operations: list[str]
    allowed_payment_protocols: list[str]
    allowed_chains: list[str]
    allowed_models: list[str]
    #: Addresses (hex) the agent may pay.
    allowed_counterparties: list[str]
    #: The KYC tier every counterparty the agent pays must hold.
    counterparty_kyc: CounterpartyKyc
    #: The most the facilitator and relayer lines of a settlement the agent opens may take, basis points.
    max_split_fee_bps: int


class _AgentTermsRequired(TypedDict):
    controller_did: str
    agent_name: str
    serving_nodes: list[ServingNodeRef]


class AgentTerms(_AgentTermsRequired, total=False):
    """What a controller approves for a delegated agent."""

    delegation_scope: DelegationScope
    capabilities: list[str]
    min_distinct_operators: int
    expires_at_ms: int


class AgentPayment(TypedDict):
    """The payment an agent's ``pay`` action makes."""

    payment_id: str
    #: SHA-256 of the request paid for, hex.
    request_digest: str
    #: The payee's quote digest, hex, or 64 zeros for none.
    quote_digest: str


class AgentStepUp(TypedDict):
    """The root's approval of one held action (``agent_step_up``).

    ``account``, ``nonce`` and ``root_public_key`` (the root's P-256 key,
    x||y) are hex; ``signature`` is the root's composite signature over the
    challenge digest under the account-owner context: ``{"classical":
    {"form": "web_authn", ...}}`` from a passkey, ``{"classical": {"form":
    "raw", "signature": ...}, "pq": ...}`` from a TPM or Secure Enclave.
    """

    account: str
    nonce: str
    root_public_key: str
    signature: dict[str, Any]


class AgentActRequest(TypedDict, total=False):
    """One action a delegated agent asks its serving node to take."""

    operation: str
    #: Recipient address, hex, when the action moves value.
    counterparty: str
    #: Value moved, wei, decimal.
    amount: str
    #: Chain; ``tenzro`` when omitted.
    chain: str
    payment_protocol: str
    model: str
    #: Asset moved other than TNZO: a token id, ``0x`` hex.
    asset: str
    #: USD price of the value moved, micro-units; required with ``asset``.
    usd_e6: int
    #: For ``pay``: what the payment pays for.
    payment: AgentPayment
    #: The controller's step-up of this exact action, when its terms hold it:
    #: the root signs the challenge a refused attempt returns in the error's
    #: ``data.step_up``, and the same action is sent again with it.
    step_up: AgentStepUp


#: Answers a custody challenge (``tenzro_createCustodyChallenge``'s result) with
#: ``{challenge_id, credential_id_hex, assertion, ml_dsa_signature_hex?}`` from
#: a passkey enrolled on the controller's smart account.
Authorize = Callable[[dict[str, Any]], dict[str, Any]]


def _completed_terms(challenge: dict[str, Any]) -> dict[str, Any]:
    delegation = challenge.get("delegation")
    if not delegation:
        raise ValueError("the node returned no completed delegation terms")
    return delegation


def delegate_agent(rpc: RpcClient, account_address: str, terms: AgentTerms, authorize: Authorize) -> Any:
    """Delegate an agent under ``terms`` with the controller's passkey.

    The node completes each serving node's key and returns a challenge over
    the completed terms; ``authorize`` signs it. The serving nodes deliver the
    agent's access tokens; the result says how each delivery went.
    """
    challenge = rpc.call(
        "tenzro_createCustodyChallenge",
        {"account_address": account_address, "operation": "delegate_agent", "delegation": terms},
    )
    delegation = _completed_terms(challenge)
    return rpc.call("tenzro_onboardDelegatedAgent", {"delegation": delegation, "authorization": authorize(challenge)})


def update_agent_terms(
    rpc: RpcClient, account_address: str, agent_did: str, terms: AgentTerms, rotate_tokens: bool, authorize: Authorize
) -> Any:
    """Replace a delegated agent's terms with the controller's passkey; the agent's DID stays the same."""
    challenge = rpc.call(
        "tenzro_createCustodyChallenge",
        {
            "account_address": account_address,
            "operation": "update_agent_terms",
            "agent_did": agent_did,
            "delegation": terms,
            "rotate_tokens": rotate_tokens,
        },
    )
    delegation = _completed_terms(challenge)
    return rpc.call(
        "tenzro_updateAgentTerms",
        {
            "agent_did": agent_did,
            "delegation": delegation,
            "rotate_tokens": rotate_tokens,
            "authorization": authorize(challenge),
        },
    )


#: The reason a revocation records when none is given.
DEFAULT_REVOCATION_REASON = "revoked by its root"


def revocation_target(did: str, reason: str) -> bytes:
    """What a root signs to revoke ``did`` for ``reason``: the target of a ``revoke_identity``
    custody challenge, SHA-256("tenzro/identity-revocation/v1" || len || did || len || reason)
    with 4-byte big-endian lengths."""
    import hashlib

    h = hashlib.sha256(b"tenzro/identity-revocation/v1")
    for field in (did.encode(), reason.encode()):
        h.update(len(field).to_bytes(4, "big"))
        h.update(field)
    return h.digest()


#: Gas a ``RevokeIdentity`` transaction is sent with: the root's approval check and room for the
#: agents a root revocation reaches.
REVOCATION_GAS_LIMIT = 1_000_000


class RootApproval(TypedDict):
    """A root's signature over a ``revoke_identity`` challenge, as a ``RevokeIdentity`` carries it."""

    #: The root's P-256 key, ``x || y`` (64 bytes), as a list of byte values.
    root_public_key: list[int]
    #: The composite signature over the challenge in its JSON form: a passkey's
    #: ``{"classical": {"form": "web_authn", "authenticator_data", "client_data_json", "signature"}}``
    #: or a machine's ``{"classical": {"form": "raw", "signature"}, "pq"}``, hex fields.
    signature: dict[str, Any]


def passkey_root_approval(
    public_key: bytes, authenticator_data: bytes, client_data_json: bytes, signature: bytes
) -> RootApproval:
    """A passkey root's approval: its P-256 key and its WebAuthn assertion over the challenge's
    ``webauthn_challenge``, as the authenticator returned it."""
    return {
        "root_public_key": list(public_key),
        "signature": {
            "classical": {
                "form": "web_authn",
                "authenticator_data": authenticator_data.hex(),
                "client_data_json": client_data_json.hex(),
                "signature": signature.hex(),
            }
        },
    }


def revoke_identity(
    rpc: RpcClient,
    signer: HybridSigner,
    account_address: str,
    did: str,
    approve: Callable[[Any], RootApproval],
    reason: str = DEFAULT_REVOCATION_REASON,
    approver_did: str | None = None,
) -> Any:
    """Revoke an identity with its root's approval: a root revokes itself, a delegated agent is revoked
    by the controller its terms name, and a machine a root registered by that root
    (``account_address`` is the approving root's account, ``approver_did`` the root, ``did`` by default).

    ``approve`` signs the ``revoke_identity`` challenge, which covers ``did`` and ``reason``. The approval
    goes into a ``RevokeIdentity`` transaction signed by ``signer`` (any account may send it; the approval
    authorises it) and submitted with ``tenzro_revokeIdentity``. Every validator re-verifies it; once it is
    in a block every node treats the identity as revoked and revokes its tokens, and revoking a root also
    revokes its agents."""
    challenge = rpc.call(
        "tenzro_createCustodyChallenge",
        {
            "account_address": account_address,
            "operation": "revoke_identity",
            "target_hex": revocation_target(did, reason).hex(),
        },
    )
    root = approve(challenge)

    def unhex(field: str) -> list[int]:
        return list(bytes.fromhex(challenge[field].removeprefix("0x")))

    op = {
        "did": did,
        "reason": reason,
        "approver_did": approver_did or did,
        "approval": {
            "account": unhex("account_address"),
            "nonce": unhex("nonce_hex"),
            "root_public_key": root["root_public_key"],
            "signature": root["signature"],
        },
    }
    tx = TypedTransaction(kind="RevokeIdentity", fields={"op": op}, gas_limit=REVOCATION_GAS_LIMIT)
    return TypedTxClient(rpc).send_via("tenzro_revokeIdentity", signer, tx)


def agent_act(rpc: RpcClient, action: AgentActRequest) -> Any:
    """One action as a delegated agent; ``rpc`` carries the agent's access credential on a serving node."""
    return rpc.call("tenzro_agentAct", dict(action))


def agent_voucher(rpc: RpcClient, channel_id: str, cumulative_amount: int) -> Any:
    """The agent's next cumulative voucher on a channel its wallet funded, signed by the serving node for the agent."""
    return rpc.call("tenzro_agentVoucher", {"channel_id": channel_id, "cumulative_amount": str(cumulative_amount)})
