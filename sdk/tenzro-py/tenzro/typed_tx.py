"""Typed transactions for every consensus transaction type, signed with the caller's hardware key.

A :class:`TypedTransaction` names its kind and carries the variant's fields as
JSON. :meth:`TypedTxClient.send` fills in the envelope, asks the node for the
signing payload, checks that the payload is the transaction it asked for,
signs the digest with the caller's hybrid key and submits it. The node never
signs: it only encodes, and an encoding that does not match what the caller
built is refused before anything is signed.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from dataclasses import dataclass
from typing import Any

from .rpc import RpcClient
from .wallet import (
    TRANSACTION_SIGNATURE_CONTEXT,
    HybridSigner,
    account_address,
    composite_message_representative,
    composite_signature_json,
)

#: Every consensus transaction type, in the order the network declares them.
TX_KINDS = (
    "Transfer",
    "ContractDeploy",
    "ContractCall",
    "AgentRegister",
    "AgentExecute",
    "ModelInference",
    "TeeProviderRegister",
    "GovernancePropose",
    "GovernanceVote",
    "GovernanceVeto",
    "GovernancePause",
    "GovernanceExecute",
    "Funding",
    "CreateEscrow",
    "ReleaseEscrow",
    "RefundEscrow",
    "PauseAgent",
    "QuarantineAgent",
    "TerminateAgent",
    "PostAgentBond",
    "IncreaseAgentBond",
    "WithdrawAgentBond",
    "PostComputeBond",
    "IncreaseComputeBond",
    "WithdrawComputeBond",
    "FinalizeComputeBondWithdrawal",
    "PayInsuranceClaim",
    "PayerSettle",
    "ClaimEscrow",
    "ClaimEscrowPreimage",
    "ClaimEscrowStream",
    "PostMeterBond",
    "WithdrawMeterBond",
    "DisputeMeteredCharge",
    "TreasuryDeposit",
    "IncreaseValidatorStake",
    "RegisterValidator",
    "ReportCheckpointEquivocation",
    "ExitValidator",
    "UpdateValidatorMetadata",
    "RegisterIdentity",
    "AttestZkProof",
    "SlaAttest",
    "ComputeClaim",
    "RecordCheckpointSigners",
    "AgentAuditCommit",
    "LiftAgentQuarantine",
    "AgentAuditFlag",
    "RevokeDelegatedAgent",
    "SetAgentTerms",
    "AgentAct",
    "FeeRateSubmit",
    "InferenceFault",
    "Bridge",
    "Token",
    "Stake",
    "RemoteGrantSettle",
    "Payment",
    "GovernanceVetoSignal",
    "GovernanceVetoWithdraw",
    "GovernanceConcern",
    "UpgradeReady",
    "GovernanceSecurityDisclosure",
    "SettlementPlan",
    "BeaconContribute",
    "DaRetention",
    "AccountKeys",
    "KeystoreUpdate",
    "IdentityServices",
    "ExternalEvm",
    "ExternalSvm",
    "RevokeIdentity",
    "Registry",
    "SetAgentTopUp",
    "TopUpAgent",
    "ReclaimAgentFunds",
    "RotateValidatorKey",
    "HardwareProof",
    "RegisterValidatorMachine",
    "KeyRelease",
    "TrainingProof",
    "AttachMachineAttestation",
    "SponsoredBond",
    "AccountOutflow",
)

#: One consensus transaction type, a member of :data:`TX_KINDS`.
TxKind = str

VALIDITY_MS = 300_000
DEFAULT_GAS_LIMIT = 500_000


@dataclass
class TypedTransaction:
    """A transaction of one kind, before its envelope and signature."""

    kind: TxKind
    #: The kind's fields; ``None`` for ``ExitValidator``, the one kind without fields.
    fields: dict[str, Any] | None
    #: Hex recipient field of the envelope; the system address when unset.
    to: str | None = None
    #: Hex sender account (20 or 32 bytes): a passkey account whose keystore on
    #: chain links the signer's passkey, such as the account every device of a
    #: wallet acts for. By default the account the signer's P-256 key names.
    from_account: str | None = None
    gas_limit: int | None = None
    gas_price: int | None = None


def tx_type(tx: TypedTransaction) -> Any:
    """The ``tx_type`` the network decodes."""
    if tx.kind not in TX_KINDS:
        raise ValueError(f"{tx.kind} is not a transaction type")
    if tx.kind == "ExitValidator":
        if tx.fields is not None:
            raise ValueError("ExitValidator takes no fields")
        return "ExitValidator"
    if not isinstance(tx.fields, dict):
        raise ValueError(f"{tx.kind} takes a JSON object of fields")
    if tx.kind == "KeystoreUpdate":
        return {"KeystoreUpdate": _keystore_update_fields(tx.fields)}
    return {tx.kind: tx.fields}


def _keystore_update_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """A keystore change as the network encodes it: a credential the change adds carries
    ``added_at_ms`` (zero; the chain sets it), as the node's signing payload does."""
    update = fields.get("update")
    op = update.get("op") if isinstance(update, dict) else None
    if not isinstance(op, dict) or len(op) != 1:
        return fields
    ((name, body),) = op.items()
    if name not in ("add_credential", "start_recovery") or not isinstance(body, dict):
        return fields
    credential = body.get("credential")
    if not isinstance(credential, dict):
        return fields
    credential = {**credential, "added_at_ms": credential.get("added_at_ms", 0)}
    return {**fields, "update": {**update, "op": {name: {**body, "credential": credential}}}}


@dataclass(frozen=True)
class Envelope:
    """The envelope fields of one signing."""

    chain_id: int
    from_: bytes
    to: bytes
    nonce: int
    gas_limit: int
    gas_price: int
    timestamp: int
    valid_until: int


_QUANTITY = re.compile(r"(0x)?[0-9a-fA-F]+")


class ChainReadError(RuntimeError):
    """A nonce, chain id or other quantity the node did not report: the read
    failed or its answer is not a hex quantity."""


def parse_quantity(value: Any) -> int:
    """A hex quantity, ``0x``-prefixed or bare. Anything else raises ``ValueError``."""
    if not isinstance(value, str) or not _QUANTITY.fullmatch(value):
        raise ValueError(f"{value!r} is not a hex quantity")
    return int(value, 16)


def read_quantity(rpc: Any, method: str, params: list[Any], what: str) -> int:
    """Read a hex quantity (a nonce, the chain id) from the node. An RPC
    failure or an answer that is not a hex quantity raises
    :class:`ChainReadError` naming the endpoint; no default stands in for it."""
    at = getattr(rpc, "endpoint", "the RPC endpoint")
    try:
        return parse_quantity(rpc.call(method, params))
    except Exception as e:
        raise ChainReadError(f"could not read the {what} from {at}: {e}") from e


class SigningPayloadMismatch(ValueError):
    """The node's signing payload is not the transaction the caller built."""

    def __init__(self, what: str):
        super().__init__(f"the node's signing payload does not match the transaction: {what}")


def _same_json(a: Any, b: Any) -> bool:
    """Equality of two JSON values: object key order ignored, a boolean never equal to a number."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same_json(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_json(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _account_slot(s: str) -> bytes:
    """A 20- or 32-byte account as its 32-byte slot."""
    b = _unhex(s)
    if len(b) == 20:
        return b + bytes(12)
    if len(b) == 32:
        return b
    raise ValueError(f"sender must be 20 or 32 bytes, got {len(b)}")


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def check_signing_payload(env: Envelope, type_: Any, payload: dict[str, Any]) -> bytes:
    """The digest to sign, once the node's payload is shown to be the transaction ``env`` and ``type_`` describe."""
    if not isinstance(payload.get("digest"), str):
        raise SigningPayloadMismatch("no digest")
    claimed = _unhex(payload["digest"])
    kind = payload.get("kind")
    if kind == "plain":
        encoded = payload.get("tx_type_json")
        if not isinstance(encoded, str):
            raise SigningPayloadMismatch("no tx_type encoding")
        if not _same_json(json.loads(encoded), type_):
            raise SigningPayloadMismatch("tx_type")
        digest = hashlib.sha256(
            struct.pack("<Q", env.chain_id)
            + env.from_
            + env.to
            + struct.pack("<QQQqq", env.nonce, env.gas_limit, env.gas_price, env.timestamp, env.valid_until)
            + encoded.encode()
        ).digest()
    elif kind == "typed_action":
        preimage = payload.get("preimage")
        if not isinstance(preimage, str):
            raise SigningPayloadMismatch("no preimage")
        p = json.loads(preimage)
        want = {
            "chain_id": env.chain_id,
            "from": env.from_.hex(),
            "to": env.to.hex(),
            "nonce": env.nonce,
            "gas_limit": env.gas_limit,
            "gas_price": env.gas_price,
            "timestamp": env.timestamp,
            "valid_until": env.valid_until,
            "action": type_,
        }
        for field, value in want.items():
            if not _same_json(p.get(field), value):
                raise SigningPayloadMismatch(field)
        digest = hashlib.sha256(preimage.encode()).digest()
    else:
        raise SigningPayloadMismatch("unknown payload kind")
    if digest != claimed:
        raise SigningPayloadMismatch("digest")
    return digest


class TypedTxClient:
    """Signs and submits typed transactions."""

    def __init__(self, rpc: RpcClient):
        self._rpc = rpc

    def send(self, signer: HybridSigner, tx: TypedTransaction) -> Any:
        """Sign ``tx`` with ``signer`` and submit it; returns ``tenzro_sendRawTransaction``'s answer."""
        return self.send_via("tenzro_sendRawTransaction", signer, tx)

    def send_via(self, method: str, signer: HybridSigner, tx: TypedTransaction) -> Any:
        """Sign ``tx`` with ``signer`` and submit it through ``method``, which takes the params
        ``tenzro_sendRawTransaction`` takes (``tenzro_revokeIdentity`` for a ``RevokeIdentity``)."""
        _, _, request, public_key, signature = self._sign_parts(signer, tx)
        return self._rpc.call(method, {**request, "public_key": public_key.hex(), "signature": signature})

    def sign(self, signer: HybridSigner, tx: TypedTransaction) -> dict[str, Any]:
        """Sign ``tx`` without submitting it: the signed transaction in the network's JSON form."""
        env, type_, _, public_key, signature = self._sign_parts(signer, tx)
        return {
            "transaction": {
                "chain_id": env.chain_id,
                "from": list(env.from_),
                "to": list(env.to),
                "nonce": env.nonce,
                "tx_type": type_,
                "gas_limit": env.gas_limit,
                "gas_price": env.gas_price,
                "timestamp": env.timestamp,
                "valid_until": env.valid_until,
                "memo": None,
            },
            "public_key": public_key.hex(),
            "signature": signature,
        }

    def prepare(self, from_account: str, tx: TypedTransaction) -> dict[str, Any]:
        """A dry run of ``tx`` sent from ``from_account`` (``tx.from_account`` wins
        when set): reads the nonce, chain id and gas price the node reports,
        asks the node to encode the signing payload and checks that the
        encoding is the transaction built here. Returns ``{"request", "digest"}``
        (the unsigned ``tenzro_sendRawTransaction`` params and the hex digest a
        signer would sign); nothing is signed or submitted."""
        from_ = _account_slot(tx.from_account if tx.from_account is not None else from_account)
        _, _, request, digest = self._prepare_parts(from_, tx)
        return {"request": request, "digest": digest.hex()}

    def _sign_parts(self, signer: HybridSigner, tx: TypedTransaction):
        public_key = signer.p256_public_key()
        from_ = account_address(public_key) if tx.from_account is None else _account_slot(tx.from_account)
        env, type_, request, digest = self._prepare_parts(from_, tx)
        m_prime = composite_message_representative(TRANSACTION_SIGNATURE_CONTEXT, digest)
        classical, pq = signer.sign_composite(m_prime)
        return env, type_, request, public_key, composite_signature_json(classical, pq)

    def _prepare_parts(self, from_: bytes, tx: TypedTransaction):
        type_ = tx_type(tx)
        to = _unhex(tx.to) if tx.to else bytes(32)
        if len(to) != 32:
            raise ValueError(f"recipient must be 32 bytes, got {len(to)}")
        nonce = read_quantity(self._rpc, "tenzro_getNonce", ["0x" + from_.hex()], "nonce")
        chain_id = read_quantity(self._rpc, "eth_chainId", [], "chain id")
        gas_price = (
            tx.gas_price if tx.gas_price is not None else read_quantity(self._rpc, "eth_gasPrice", [], "gas price")
        )
        timestamp = int(time.time() * 1000)
        env = Envelope(
            chain_id=chain_id,
            from_=from_,
            to=to,
            nonce=nonce,
            gas_limit=tx.gas_limit if tx.gas_limit is not None else DEFAULT_GAS_LIMIT,
            gas_price=gas_price,
            timestamp=timestamp,
            valid_until=timestamp + VALIDITY_MS,
        )
        request = {
            "from": "0x" + from_.hex(),
            "to": "0x" + to.hex(),
            "nonce": nonce,
            "chain_id": chain_id,
            "gas_limit": env.gas_limit,
            "gas_price": env.gas_price,
            "timestamp": timestamp,
            "valid_until": env.valid_until,
            "tx_type": type_,
        }
        payload = self._rpc.call("tenzro_getSigningPayload", request)
        digest = check_signing_payload(env, type_, payload)
        return env, type_, request, digest
