"""A machine root's governance ballot.

A validator whose identity is an autonomous machine votes by its machine
root: the hardware key its machine DID derives from approves exactly one
ballot, and the approval travels as ``GovernanceVote.root_approval``. Any
account may submit the transaction.
"""

from __future__ import annotations

import hashlib
import os
import struct

from .wallet import HybridSigner, composite_message_representative, composite_signature_json

#: Signature context of a root's custody approval.
ACCOUNT_OWNER_SIGNATURE_CONTEXT = b"tenzro/rpc/account-owner"


def governance_ballot_digest(
    chain_id: int, account: bytes, proposal_id: bytes, vote: bool, validator: bytes, nonce: bytes
) -> bytes:
    """The custody digest a machine root signs for its validator's ballot on the network ``chain_id``."""
    target = proposal_id + bytes([1 if vote else 0, len(validator)]) + validator
    h = hashlib.sha256(b"tenzro/custody-challenge/v2")
    h.update(struct.pack(">Q", chain_id))
    for part in (account, b"governance_ballot", target):
        h.update(struct.pack(">I", len(part)))
        h.update(part)
    h.update(nonce)
    return h.digest()


def machine_root_ballot(signer: HybridSigner, chain_id: int, proposal_id_hex: str, vote: bool, validator_hex: str) -> dict:
    """The ``root_approval`` of a ``GovernanceVote`` on the network ``chain_id`` for the validator that is the machine holding ``signer``."""
    proposal_id = bytes.fromhex(proposal_id_hex.removeprefix("0x"))
    validator = bytes.fromhex(validator_hex.removeprefix("0x"))
    if len(proposal_id) != 32:
        raise ValueError("proposal_id is 32 bytes")
    if len(validator) != 32:
        raise ValueError("validator is a 32-byte account")
    nonce = os.urandom(16)
    digest = governance_ballot_digest(chain_id, validator, proposal_id, vote, validator, nonce)
    classical, ml_dsa = signer.sign_composite(composite_message_representative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, digest))
    return {
        "account": list(validator),
        "nonce": list(nonce),
        "root_public_key": list(signer.p256_public_key()),
        "signature": composite_signature_json(classical, ml_dsa),
    }
