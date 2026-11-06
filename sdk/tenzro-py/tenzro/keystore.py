"""Passkey account keystores, held in consensus state.

A passkey account is its devices plus its keystore on the ledger: the passkeys
that may act for it, its policy, its recovery signers and any recovery in
progress. Every node answers from the same record, so any linked device works
through any node. Changes are ``KeystoreUpdate`` transactions, approved by the
account's passkeys (or, to start a recovery, its recovery signers) over
:func:`keystore_digest`, which every SDK computes the same way and which names
the chain the change is for: a chain refuses a change approved for another.
Any account may send and pay for one.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from .rpc import RpcClient
from .typed_tx import TypedTransaction, TypedTxClient, read_quantity
from .wallet import HybridSigner, composite_message_representative, composite_signature_json

#: Context passkeys approve keystore changes under.
ACCOUNT_OWNER_SIGNATURE_CONTEXT = b"tenzro/rpc/account-owner"
#: Context recovery signers approve a recovery under.
RECOVERY_APPROVAL_SIGNATURE_CONTEXT = b"tenzro/identity/recovery-approval"

_UPDATE_DOMAIN = b"tenzro/keystore-update/v1"
_ROLE = {"recovery_key": 1, "email_verifier": 2, "device": 3}
_POLICY = {"single_credential": 1, "two_credentials": 2}


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.removeprefix("0x"))


def _field(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _credential(c: dict[str, Any]) -> bytes:
    return (
        _field(c["rp_id"].encode())
        + _field(_b(c["credential_id"]))
        + _field(_b(c["public_key"]))
        + _field(_b(c["aaguid"]))
        + bytes([int(bool(c["backup_eligible"])), int(bool(c["backup_state"]))])
        + _field(c["label"].encode())
    )


def encode_keystore_op(op: Any) -> bytes:
    """The canonical bytes of ``op`` (its JSON form) an approval covers."""
    if op == "cancel_recovery":
        return b"\x05"
    if op == "finish_recovery":
        return b"\x06"
    ((kind, v),) = op.items()
    if kind == "add_credential":
        return b"\x01" + _credential(v["credential"])
    if kind == "remove_credential":
        return b"\x02" + _field(_b(v["credential_id"]))
    if kind == "set_recovery":
        out = b"\x03" + struct.pack(">I", v["threshold"]) + struct.pack(">I", len(v["signers"]))
        for s in v["signers"]:
            out += (
                _field(s["rp_id"].encode())
                + _field(_b(s["public_key"]))
                + _field(_b(s["aaguid"]))
                + bytes([int(bool(s["backup_eligible"])), int(bool(s["backup_state"])), _ROLE[s["role"]]])
                + _field(s["label"].encode())
            )
        return out
    if kind == "start_recovery":
        return b"\x04" + _credential(v["credential"])
    if kind == "set_policy":
        return b"\x07" + bytes([_POLICY[v["policy"]]])
    if kind == "set_recovery_code":
        return b"\x08" + _field(_b(v["commitment"]) if v["commitment"] else b"")
    if kind == "claim_recovery_code":
        return b"\x09" + _field(_b(v["claim"]))
    if kind == "recover_with_code":
        return b"\x0a" + _field(_b(v["code"])) + _credential(v["credential"])
    raise ValueError(f"unknown keystore change {kind}")


_RECOVERY_CODE_DOMAIN = b"tenzro/keystore/recovery-code/v1"
_RECOVERY_CLAIM_DOMAIN = b"tenzro/keystore/recovery-claim/v1"


def _chain(chain_id: int) -> bytes:
    return struct.pack("<Q", chain_id)


def recovery_code_commitment(chain_id: int, account: str, code: str) -> bytes:
    """The commitment an account on chain ``chain_id`` holds for its one-time
    recovery code (``code``, 32 bytes hex, kept by its holder):
    ``set_recovery_code`` sets it."""
    return hashlib.sha256(_RECOVERY_CODE_DOMAIN + _chain(chain_id) + _b(account) + _b(code)).digest()


def recovery_code_claim(chain_id: int, account: str, code: str, credential: dict[str, Any]) -> bytes:
    """The claim on chain ``chain_id`` that binds the recovery code to the
    passkey that will join: sent first, by another account, as
    ``claim_recovery_code``; the code is revealed with ``recover_with_code``
    once the claim has aged."""
    return hashlib.sha256(
        _RECOVERY_CLAIM_DOMAIN + _chain(chain_id) + _b(account) + _b(code) + _credential(credential)
    ).digest()


def keystore_digest(chain_id: int, account: str, previous_commitment: str, op: Any) -> bytes:
    """What every approval of ``op`` on ``account`` on chain ``chain_id`` signs,
    given the commitment of the record it changes:
    ``SHA-256(domain ‖ chain id ‖ account ‖ commitment ‖ op)``, the chain id as
    8 bytes little-endian."""
    return hashlib.sha256(
        _UPDATE_DOMAIN
        + _chain(chain_id)
        + _field(_b(account))
        + _field(_b(previous_commitment))
        + encode_keystore_op(op)
    ).digest()


def _update_digest(update: dict[str, Any]) -> bytes:
    return keystore_digest(update["chain_id"], update["account"], update["previous_commitment"], update["op"])


def _sign(signer: HybridSigner, context: bytes, digest: bytes) -> dict[str, Any]:
    classical, pq = signer.sign_composite(composite_message_representative(context, digest))
    return composite_signature_json(classical, pq)


class KeystoreClient:
    """Reads keystores and builds, approves and sends their changes."""

    def __init__(self, rpc: RpcClient):
        self._rpc = rpc
        self._txs = TypedTxClient(rpc)

    def get_keystore(self, account: str, anchor: dict[str, Any] | None = None) -> Any:
        """The keystore of ``account``; with ``anchor``, the genesis record of an account that has none on chain."""
        params: dict[str, Any] = {"account": account}
        if anchor is not None:
            params["anchor"] = anchor
        return self._rpc.call("tenzro_getKeystore", params)

    def resolve_credential(self, credential_id: str, rp_id: str) -> Any:
        """The accounts whose keystore links the passkey with this credential id, registered on ``rp_id``."""
        return self._rpc.call("tenzro_resolveCredential", {"credential_id": credential_id, "rp_id": rp_id})

    def prepare(self, account: str, op: Any, anchor: dict[str, Any] | None = None) -> dict[str, Any]:
        """An unapproved change naming the node's chain and the keystore's
        current commitment."""
        view = self.get_keystore(account, anchor)
        if not view.get("keystore") or not view.get("commitment"):
            raise ValueError(f"account {account} has no keystore on chain; pass its anchor")
        return {
            "chain_id": read_quantity(self._rpc, "eth_chainId", [], "chain id"),
            "account": view["account"],
            "anchor": None if view["on_chain"] else anchor,
            "previous_commitment": view["commitment"],
            "op": op,
            "approvals": [],
            "possession": None,
        }

    @staticmethod
    def approve(update: dict[str, Any], signer: HybridSigner, recovery: bool = False) -> dict[str, Any]:
        """Add ``signer``'s approval: as a passkey of the account, or with
        ``recovery`` as one of its recovery signers."""
        digest = _update_digest(update)
        context = RECOVERY_APPROVAL_SIGNATURE_CONTEXT if recovery else ACCOUNT_OWNER_SIGNATURE_CONTEXT
        approval = {"public_key": bytes(signer.p256_public_key()).hex(), "signature": _sign(signer, context, digest)}
        return {**update, "approvals": [*update["approvals"], approval]}

    @staticmethod
    def prove(update: dict[str, Any], new_passkey: HybridSigner) -> dict[str, Any]:
        """Add the proof of possession of the passkey the change adds."""
        digest = _update_digest(update)
        return {**update, "possession": _sign(new_passkey, ACCOUNT_OWNER_SIGNATURE_CONTEXT, digest)}

    def send(
        self,
        sender: HybridSigner,
        update: dict[str, Any],
        from_account: str | None = None,
        gas_price: int | None = None,
    ) -> Any:
        """Send ``update``, signed and paid for by ``sender``; with ``from_account`` from the passkey account itself.

        Without ``from_account`` the sender is a sponsor paying for an account with no balance: it
        authorizes nothing, the change carrying the passkeys' approvals. The fee is paid at
        ``gas_price``, or at the node's current price (``eth_gasPrice``).
        """
        return self._txs.send(
            sender,
            TypedTransaction(
                kind="KeystoreUpdate", fields={"update": update}, from_account=from_account, gas_price=gas_price
            ),
        )
