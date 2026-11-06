from tenzro.recipient_guard import (
    LOOKS_LIKE,
    LookalikeParams,
    assess_recipient,
    confirmation_matches,
)


def addr(first: str, mid: str, last: str) -> str:
    return "0x" + first + mid * 26 + last


REAL = addr("010203", "09", "070809")
FAKE = addr("010203", "05", "070809")


def test_trusted_has_no_friction():
    assert not assess_recipient(REAL, [REAL]).requires_full_address_confirmation


def test_first_time_is_flagged():
    assert assess_recipient(REAL, []).requires_full_address_confirmation


def test_poisoned_lookalike_is_flagged():
    a = assess_recipient(FAKE, [REAL], [FAKE])
    assert a.is_lookalike
    assert any(k == LOOKS_LIKE and o == REAL[2:] for k, o in a.flags)
    assert len(a.full_address) == 64


def test_different_ends_not_lookalike():
    other = addr("040203", "05", "070809")
    assert not assess_recipient(other, [REAL]).is_lookalike


def test_zero_width_never_matches():
    assert not assess_recipient(FAKE, [REAL], [], LookalikeParams(0, 0)).is_lookalike


def test_only_full_address_confirms():
    a = assess_recipient(REAL, [])
    assert confirmation_matches(a, REAL.upper().replace("0X", "0x"))
    assert not confirmation_matches(a, REAL[:30])
