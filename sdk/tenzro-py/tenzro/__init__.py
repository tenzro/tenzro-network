"""Tenzro Network SDK for Python.

- :class:`RpcClient` / :class:`AsyncRpcClient`: every JSON-RPC method the node
  serves, one typed method each, generated from the node's method table.
- :mod:`tenzro.typed_tx`: transactions of every consensus type, signed with
  the caller's hardware key (:mod:`tenzro.signer`; no software keys).

The package root is the thin core: the RPC clients, the signer interface and
hardware signer, typed transaction builders and the SSE decoder. Each
capability is a subpackage over it:

- :mod:`tenzro.payments`: x402 payers, the publisher gate (ASGI and WSGI
  middleware) and the publisher policy.
- :mod:`tenzro.settlement`: the split engine, settlement plans, refunds,
  payee split rules, and plan, decision and leg receipt reads.
- :mod:`tenzro.agents`: delegated agents' Terms and actions within them,
  kill-switch receipts and quarantine state.
- :mod:`tenzro.admin`: the node's administrative audit log (operator only).
- :mod:`tenzro.bridge`: bridge sends, agents' accounts on other chains and
  EIP-7702 set-code transactions.
- :mod:`tenzro.inference`: streamed chat completions.
- :mod:`tenzro.chain`: offline verification of governance receipts, ABI
  encoding and decoding, and NFT factory calls and their results.
"""

from .did_envelope import DID_ENVELOPE_CONTEXT, DidEnvelopeFields, request_binding, with_request_envelope
from .keystore import KeystoreClient, encode_keystore_op, keystore_digest
from .network import (
    NETWORK_CHAIN_ID,
    NETWORK_SEEDS,
    PREVIEW_NETWORK,
    CheckedEndpoint,
    NetworkPreset,
    NetworkRpcClient,
    discover_endpoints,
)
from .root_ballot import governance_ballot_digest, machine_root_ballot
from .rpc import METHODS, AccessCredential, ApiError, AsyncRpcClient, RpcClient, RpcError
from .sse import SseDecoder, SseEvent
from .signer import (
    DeviceKeySigner,
    HardwareDpopProver,
    NoHardwareSigner,
    open_hardware_signer,
    platform_backend,
    set_key_namespace,
)
from .typed_tx import TX_KINDS, TypedTransaction, TypedTxClient, tx_type
from .wallet import (
    TRANSACTION_SIGNATURE_CONTEXT,
    HybridSigner,
    WebAuthnAssertion,
    account_address,
    composite_message_representative,
    composite_signature_json,
)

__version__ = "0.2.0"

__all__ = [
    "DID_ENVELOPE_CONTEXT",
    "DidEnvelopeFields",
    "request_binding",
    "with_request_envelope",
    "KeystoreClient",
    "encode_keystore_op",
    "keystore_digest",
    "METHODS",
    "TRANSACTION_SIGNATURE_CONTEXT",
    "TX_KINDS",
    "AccessCredential",
    "ApiError",
    "AsyncRpcClient",
    "CheckedEndpoint",
    "DeviceKeySigner",
    "HardwareDpopProver",
    "HybridSigner",
    "NETWORK_CHAIN_ID",
    "NETWORK_SEEDS",
    "PREVIEW_NETWORK",
    "NetworkPreset",
    "NetworkRpcClient",
    "NoHardwareSigner",
    "RpcClient",
    "RpcError",
    "SseDecoder",
    "SseEvent",
    "TypedTransaction",
    "TypedTxClient",
    "WebAuthnAssertion",
    "account_address",
    "composite_message_representative",
    "composite_signature_json",
    "discover_endpoints",
    "governance_ballot_digest",
    "machine_root_ballot",
    "open_hardware_signer",
    "set_key_namespace",
    "platform_backend",
    "tx_type",
]
