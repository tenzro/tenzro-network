"""Tenzro Cross-VM (SVM-native) program — instruction builders.

The Tenzro Cross-VM program is a native SVM program (no SBF ELF) that lets SVM
transactions initiate cross-VM token transfers. The SVM executor recognizes
``TENZRO_CROSS_VM_PROGRAM_ID_BASE58`` and dispatches to the native handlers in
``tenzro_vm::svm::cross_vm``.

Authoritative source: ``crates/tenzro-vm/src/svm/cross_vm.rs``. Constants here
MUST stay byte-identical to the Rust constants.

- **Program ID**: ``SHA-256("tenzro/svm/program/cross_vm/v1")``

  - Hex: ``918f858b6b0dd134e9a1fcb73002428c5197093e76e536badc60382bb9f8ac78``
  - Base58: ``AoD3kebB2bYjLKyJtaqkyXqwJy4oQ949SnVhMwEYzGXR``

- **Instruction discriminators**: 8-byte Anchor-style
  ``SHA-256("global:<snake_case_name>")[..8]``.

- **Instruction data layout**: ``[ discriminator (8) | payload (n) ]``. All
  integers are little-endian; byte arrays are inlined.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Union


# ---------------------------------------------------------------------------
# Program ID
# ---------------------------------------------------------------------------

TENZRO_CROSS_VM_PROGRAM_ID: bytes = bytes([
    0x91, 0x8f, 0x85, 0x8b, 0x6b, 0x0d, 0xd1, 0x34,
    0xe9, 0xa1, 0xfc, 0xb7, 0x30, 0x02, 0x42, 0x8c,
    0x51, 0x97, 0x09, 0x3e, 0x76, 0xe5, 0x36, 0xba,
    0xdc, 0x60, 0x38, 0x2b, 0xb9, 0xf8, 0xac, 0x78,
])

TENZRO_CROSS_VM_PROGRAM_ID_HEX = (
    "918f858b6b0dd134e9a1fcb73002428c5197093e76e536badc60382bb9f8ac78"
)

TENZRO_CROSS_VM_PROGRAM_ID_BASE58 = "AoD3kebB2bYjLKyJtaqkyXqwJy4oQ949SnVhMwEYzGXR"

PROGRAM_ID_DERIVATION_DOMAIN = "tenzro/svm/program/cross_vm/v1"


# ---------------------------------------------------------------------------
# Instruction discriminators (Anchor-style: SHA-256("global:<name>")[..8])
# ---------------------------------------------------------------------------

DISCRIMINATOR_BRIDGE_TO_EVM = bytes(
    [0x92, 0xa8, 0xa4, 0x5c, 0x33, 0x22, 0x5f, 0x25]
)
DISCRIMINATOR_BRIDGE_FROM_EVM = bytes(
    [0x30, 0x38, 0x73, 0x32, 0x89, 0xf4, 0xcd, 0x75]
)
DISCRIMINATOR_REGISTER_TOKEN_POINTER = bytes(
    [0x9a, 0x8e, 0x01, 0x39, 0x0f, 0x99, 0x45, 0x22]
)
DISCRIMINATOR_TRANSFER_CROSS_VM = bytes(
    [0xbc, 0x68, 0x41, 0x68, 0xab, 0xa7, 0xab, 0xb9]
)


# ---------------------------------------------------------------------------
# Payload sizes (excluding the 8-byte discriminator)
# ---------------------------------------------------------------------------

PAYLOAD_SIZE_BRIDGE_TO_EVM = 68            # 32 + 20 + 8 + 8
PAYLOAD_SIZE_BRIDGE_FROM_EVM = 80          # 32 + 32 + 8 + 8
PAYLOAD_SIZE_REGISTER_TOKEN_POINTER = 84   # 32 + 20 + 32
PAYLOAD_SIZE_TRANSFER_CROSS_VM = 81        # 32 + 1 + 32 + 8 + 8


# ---------------------------------------------------------------------------
# VM type tags (matches cross_vm_bridge::VM_TYPE_*)
# ---------------------------------------------------------------------------

VM_TYPE_NATIVE = 0
VM_TYPE_EVM = 1
VM_TYPE_SVM = 2
VM_TYPE_DAML = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _u64_le(value: int) -> bytes:
    if not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f"u64 out of range: {value}")
    return value.to_bytes(8, "little", signed=False)


def _expect_len(value: bytes, expected: int, field: str) -> None:
    if len(value) != expected:
        raise ValueError(
            f"{field}: expected {expected} bytes, got {len(value)}"
        )


def compute_discriminator(instruction_name: str) -> bytes:
    """Recompute an Anchor-style 8-byte discriminator at runtime.

    Useful for tests; production code uses the module-level constants.
    """
    h = hashlib.sha256()
    h.update(b"global:")
    h.update(instruction_name.encode("utf-8"))
    return h.digest()[:8]


def verify_program_id() -> bool:
    """Verify TENZRO_CROSS_VM_PROGRAM_ID matches the canonical derivation."""
    return (
        hashlib.sha256(PROGRAM_ID_DERIVATION_DOMAIN.encode("utf-8")).digest()
        == TENZRO_CROSS_VM_PROGRAM_ID
    )


# ---------------------------------------------------------------------------
# Encoders — produce raw instruction-data bytes (discriminator + payload)
# ---------------------------------------------------------------------------

def encode_bridge_to_evm(
    mint: bytes,
    evm_dest: bytes,
    amount: int,
    nonce: int,
) -> bytes:
    """`bridge_to_evm(mint, evm_dest, amount, nonce)` — burn on SVM, credit EVM."""
    _expect_len(mint, 32, "mint")
    _expect_len(evm_dest, 20, "evm_dest")
    return (
        DISCRIMINATOR_BRIDGE_TO_EVM
        + bytes(mint)
        + bytes(evm_dest)
        + _u64_le(amount)
        + _u64_le(nonce)
    )


def encode_bridge_from_evm(
    mint: bytes,
    svm_dest: bytes,
    amount: int,
    nonce: int,
) -> bytes:
    """`bridge_from_evm(mint, svm_dest, amount, nonce)` — mint on SVM after EVM burn."""
    _expect_len(mint, 32, "mint")
    _expect_len(svm_dest, 32, "svm_dest")
    return (
        DISCRIMINATOR_BRIDGE_FROM_EVM
        + bytes(mint)
        + bytes(svm_dest)
        + _u64_le(amount)
        + _u64_le(nonce)
    )


def encode_register_token_pointer(
    mint: bytes,
    evm_token_address: bytes,
    token_id: bytes,
) -> bytes:
    """`register_token_pointer(mint, evm_token_address, token_id)`."""
    _expect_len(mint, 32, "mint")
    _expect_len(evm_token_address, 20, "evm_token_address")
    _expect_len(token_id, 32, "token_id")
    return (
        DISCRIMINATOR_REGISTER_TOKEN_POINTER
        + bytes(mint)
        + bytes(evm_token_address)
        + bytes(token_id)
    )


def encode_transfer_cross_vm(
    mint: bytes,
    dest_vm: int,
    dest_address: bytes,
    amount: int,
    nonce: int,
) -> bytes:
    """`transfer_cross_vm(mint, dest_vm, dest_address, amount, nonce)`."""
    _expect_len(mint, 32, "mint")
    _expect_len(dest_address, 32, "dest_address")
    if not (VM_TYPE_NATIVE <= dest_vm <= VM_TYPE_DAML):
        raise ValueError(f"dest_vm out of range: {dest_vm} (must be 0..=3)")
    return (
        DISCRIMINATOR_TRANSFER_CROSS_VM
        + bytes(mint)
        + bytes([dest_vm])
        + bytes(dest_address)
        + _u64_le(amount)
        + _u64_le(nonce)
    )


# ---------------------------------------------------------------------------
# Decoders — parse raw instruction-data bytes into typed shapes
# ---------------------------------------------------------------------------

@dataclass
class BridgeToEvm:
    mint: bytes
    evm_dest: bytes
    amount: int
    nonce: int


@dataclass
class BridgeFromEvm:
    mint: bytes
    svm_dest: bytes
    amount: int
    nonce: int


@dataclass
class RegisterTokenPointer:
    mint: bytes
    evm_token_address: bytes
    token_id: bytes


@dataclass
class TransferCrossVm:
    mint: bytes
    dest_vm: int
    dest_address: bytes
    amount: int
    nonce: int


CrossVmInstruction = Union[
    BridgeToEvm,
    BridgeFromEvm,
    RegisterTokenPointer,
    TransferCrossVm,
]


def decode_cross_vm_instruction(data: bytes) -> CrossVmInstruction:
    """Parse instruction-data bytes (discriminator + payload) into a typed
    instruction. Does not perform semantic validation."""
    if len(data) < 8:
        raise ValueError(
            f"instruction data too short: need at least 8 bytes for "
            f"discriminator, got {len(data)}"
        )
    disc = bytes(data[:8])
    payload = bytes(data[8:])

    if disc == DISCRIMINATOR_BRIDGE_TO_EVM:
        if len(payload) != PAYLOAD_SIZE_BRIDGE_TO_EVM:
            raise ValueError(
                f"bridge_to_evm payload size mismatch: expected "
                f"{PAYLOAD_SIZE_BRIDGE_TO_EVM}, got {len(payload)}"
            )
        return BridgeToEvm(
            mint=payload[0:32],
            evm_dest=payload[32:52],
            amount=int.from_bytes(payload[52:60], "little"),
            nonce=int.from_bytes(payload[60:68], "little"),
        )

    if disc == DISCRIMINATOR_BRIDGE_FROM_EVM:
        if len(payload) != PAYLOAD_SIZE_BRIDGE_FROM_EVM:
            raise ValueError(
                f"bridge_from_evm payload size mismatch: expected "
                f"{PAYLOAD_SIZE_BRIDGE_FROM_EVM}, got {len(payload)}"
            )
        return BridgeFromEvm(
            mint=payload[0:32],
            svm_dest=payload[32:64],
            amount=int.from_bytes(payload[64:72], "little"),
            nonce=int.from_bytes(payload[72:80], "little"),
        )

    if disc == DISCRIMINATOR_REGISTER_TOKEN_POINTER:
        if len(payload) != PAYLOAD_SIZE_REGISTER_TOKEN_POINTER:
            raise ValueError(
                f"register_token_pointer payload size mismatch: expected "
                f"{PAYLOAD_SIZE_REGISTER_TOKEN_POINTER}, got {len(payload)}"
            )
        return RegisterTokenPointer(
            mint=payload[0:32],
            evm_token_address=payload[32:52],
            token_id=payload[52:84],
        )

    if disc == DISCRIMINATOR_TRANSFER_CROSS_VM:
        if len(payload) != PAYLOAD_SIZE_TRANSFER_CROSS_VM:
            raise ValueError(
                f"transfer_cross_vm payload size mismatch: expected "
                f"{PAYLOAD_SIZE_TRANSFER_CROSS_VM}, got {len(payload)}"
            )
        dest_vm = payload[32]
        if dest_vm > VM_TYPE_DAML:
            raise ValueError(f"invalid dest_vm: {dest_vm} (must be 0..=3)")
        return TransferCrossVm(
            mint=payload[0:32],
            dest_vm=dest_vm,
            dest_address=payload[33:65],
            amount=int.from_bytes(payload[65:73], "little"),
            nonce=int.from_bytes(payload[73:81], "little"),
        )

    raise ValueError(f"unknown discriminator: {disc.hex()}")


__all__ = [
    "TENZRO_CROSS_VM_PROGRAM_ID",
    "TENZRO_CROSS_VM_PROGRAM_ID_HEX",
    "TENZRO_CROSS_VM_PROGRAM_ID_BASE58",
    "PROGRAM_ID_DERIVATION_DOMAIN",
    "DISCRIMINATOR_BRIDGE_TO_EVM",
    "DISCRIMINATOR_BRIDGE_FROM_EVM",
    "DISCRIMINATOR_REGISTER_TOKEN_POINTER",
    "DISCRIMINATOR_TRANSFER_CROSS_VM",
    "PAYLOAD_SIZE_BRIDGE_TO_EVM",
    "PAYLOAD_SIZE_BRIDGE_FROM_EVM",
    "PAYLOAD_SIZE_REGISTER_TOKEN_POINTER",
    "PAYLOAD_SIZE_TRANSFER_CROSS_VM",
    "VM_TYPE_NATIVE",
    "VM_TYPE_EVM",
    "VM_TYPE_SVM",
    "VM_TYPE_DAML",
    "compute_discriminator",
    "verify_program_id",
    "encode_bridge_to_evm",
    "encode_bridge_from_evm",
    "encode_register_token_pointer",
    "encode_transfer_cross_vm",
    "decode_cross_vm_instruction",
    "BridgeToEvm",
    "BridgeFromEvm",
    "RegisterTokenPointer",
    "TransferCrossVm",
    "CrossVmInstruction",
]
