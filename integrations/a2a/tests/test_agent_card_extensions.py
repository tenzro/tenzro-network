"""The Agent Card is how a counterparty discovers what we can transact in.

AP2 and x402 are both fully implemented in `tenzro-payments`, but an
implementation a peer cannot see is an implementation it will not use: the AP2
spec says support is declared in `capabilities.extensions`, and a peer branches
on that array rather than on prose in a skill description. These tests fail if
the declaration is dropped, because losing it degrades interop silently — every
call still succeeds, peers simply stop offering to pay.
"""

from tenzro_a2a_server.agent_card import build_agent_card

AP2_URI = "https://github.com/google-agentic-commerce/ap2/v1"
X402_URI = "https://github.com/google-a2a/a2a-x402/v0.1"


def _extensions() -> list[dict]:
    return build_agent_card()["capabilities"]["extensions"]


def test_ap2_extension_is_declared():
    assert any(e["uri"] == AP2_URI for e in _extensions())


def test_x402_extension_is_declared():
    assert any(e["uri"] == X402_URI for e in _extensions())


def test_every_extension_carries_uri_description_and_required():
    # The three fields the spec makes mandatory. A declaration missing
    # `required` is ambiguous to a client deciding whether it may proceed.
    for e in _extensions():
        assert set(e) >= {"uri", "description", "required"}
        assert isinstance(e["required"], bool)
        assert e["description"].strip()


def test_extensions_are_not_required():
    # Deliberate: most Tenzro skills are free, and a model served at Network
    # visibility is reachable by payment alone with no prior relationship.
    # Marking AP2 required would refuse callers we want to serve.
    assert all(e["required"] is False for e in _extensions())


def test_uris_are_exact():
    # These strings are identifiers, not URLs to fetch — a peer matches them
    # byte-for-byte, so a "harmless" reformat breaks discovery.
    uris = {e["uri"] for e in _extensions()}
    assert AP2_URI in uris and X402_URI in uris
