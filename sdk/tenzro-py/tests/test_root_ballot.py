"""The digest a machine root signs for a ballot is the chain's."""

from tenzro.root_ballot import governance_ballot_digest


def test_the_ballot_digest_matches_the_chains():
    digest = governance_ballot_digest(13380, b"\x11" * 32, b"\xab" * 32, True, b"\x22" * 32, b"\x05" * 16)
    assert digest.hex() == "cb7ff4bed1bbc009122add80adb1a59663fa621e7234251e9017c53f8bbb0192"
