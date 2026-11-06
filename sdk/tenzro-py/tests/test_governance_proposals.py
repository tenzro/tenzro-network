"""Governance proposal builders: the proposal bytes are the action the node reads."""

import json

import pytest

from tenzro.chain import parameter_change_proposal, reinstate_validator_proposal

VALIDATOR = "ab" * 32


def _action(tx):
    assert tx.kind == "GovernancePropose"
    return json.loads(bytes(tx.fields["proposal"]))


def test_reinstate_validator_carries_the_account_as_32_bytes():
    action = _action(reinstate_validator_proposal("0x" + VALIDATOR, "wrongly jailed"))
    assert action == {"action": "reinstate_validator", "validator": [0xAB] * 32, "memo": "wrongly jailed"}


@pytest.mark.parametrize("bad", ["ab" * 31, "zz" * 32, ""])
def test_reinstate_validator_refuses_a_malformed_account(bad):
    with pytest.raises(ValueError):
        reinstate_validator_proposal(bad, "memo")


def test_pausing_a_lever_is_an_ordinary_parameter_change():
    action = _action(parameter_change_proposal("bridge.status", 1, "fault"))
    assert action["action"] == "parameter_change" and action["value"] == 1
