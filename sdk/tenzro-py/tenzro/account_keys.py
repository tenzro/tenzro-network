"""Operations on the keys of the signer's own account."""

from __future__ import annotations

from typing import Any

from .rpc import RpcClient
from .typed_tx import TypedTransaction, TypedTxClient
from .wallet import HybridSigner, account_address, composite_message_representative

#: Length of an ML-DSA-65 verifying key.
ML_DSA_65_PUBLIC_KEY_LEN = 1952

#: Signature context of the proof that the hardware holds the ML-DSA-65 key being enrolled.
PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT = b"tenzro/account/pq-key-enrollment"


def pq_enrollment_message(account_slot: bytes, ml_dsa_public_key: bytes) -> bytes:
    """The account slot of the sender's P-256 key followed by the new key: what the new key signs."""
    if len(account_slot) != 32:
        raise ValueError(f"an account slot is 32 bytes, got {len(account_slot)}")
    return bytes(account_slot) + bytes(ml_dsa_public_key)


def enroll_pq_key_op(ml_dsa_public_key: bytes, possession: bytes) -> dict[str, Any]:
    """The ``op`` of an ``AccountKeys`` transaction that enrolls (or replaces) the account's ML-DSA-65 key."""
    if len(ml_dsa_public_key) != ML_DSA_65_PUBLIC_KEY_LEN:
        raise ValueError(f"an ML-DSA-65 key is {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {len(ml_dsa_public_key)}")
    if not possession:
        raise ValueError("the proof of possession is empty")
    return {"enroll_pq_key": {"ml_dsa_public_key": bytes(ml_dsa_public_key).hex(), "possession": bytes(possession).hex()}}


class AccountKeysClient:
    def __init__(self, rpc: RpcClient):
        self._rpc = rpc

    def enroll_pq_key(self, signer: HybridSigner) -> Any:
        """Enroll the hardware's ML-DSA-65 key as the account's post-quantum key, or replace the enrolled one.

        The hardware signs the proof of possession and the transaction; no key leaves it.
        """
        key = signer.ml_dsa_public_key()
        if not key:
            raise ValueError("the hardware holds no ML-DSA-65 key to enroll")
        slot = account_address(signer.p256_public_key())
        m_prime = composite_message_representative(PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT, pq_enrollment_message(slot, key))
        _, possession = signer.sign_composite(m_prime)
        if not possession:
            raise ValueError("the hardware did not sign with its ML-DSA-65 key")
        return TypedTxClient(self._rpc).send(
            signer, TypedTransaction(kind="AccountKeys", fields={"op": enroll_pq_key_op(key, possession)})
        )

    def send_enrolling(self, signer: HybridSigner, tx: TypedTransaction) -> Any:
        """Send ``tx``; if the node answers that the account has no ML-DSA-65 key enrolled, enroll the hardware's key and send it again.

        An account signs nothing until it has enrolled one, so this is how a new account sends its first transaction.
        """
        client = TypedTxClient(self._rpc)
        try:
            return client.send(signer, tx)
        except Exception as e:
            if tx.kind == "AccountKeys" or NOT_ENROLLED not in str(e):
                raise
        self.enroll_pq_key(signer)
        return client.send(signer, tx)


#: What a node answers when an account that has not enrolled an ML-DSA-65 key sends a transaction carrying that leg.
NOT_ENROLLED = "no ML-DSA-65 key enrolled"
