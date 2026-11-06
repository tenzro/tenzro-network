"""The target a root signs to revoke an identity, pinned to the chain's vector."""

from tenzro.agents import revocation_target


def test_the_revocation_target_matches_the_chains():
    assert (
        revocation_target("did:tenzro:human:aa", "passkey lost").hex()
        == "9fae58244604f04767ff22e0809efecc7f459c45eccc23b9e61499488acb170a"
    )


def test_the_target_binds_the_did_and_the_reason():
    t = revocation_target("did:tenzro:human:aa", "passkey lost")
    assert t != revocation_target("did:tenzro:human:ab", "passkey lost")
    assert t != revocation_target("did:tenzro:human:aa", "fraud")
