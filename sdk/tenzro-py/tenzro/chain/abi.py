"""Solidity ABI encoding and decoding, offline.

Types: ``uint<M>``, ``int<M>``, ``address``, ``bool``, ``bytes<M>``,
``bytes``, ``string``, arrays ``T[]`` and ``T[k]``, and tuples
``(T1,T2,...)``.

Values in: integers as ``int`` or a decimal or ``0x`` string; addresses as
``0x`` hex; byte strings as ``bytes`` or ``0x`` hex; arrays and tuples as
lists or tuples. Values out: integers as ``int``, addresses and byte strings
as lowercase ``0x`` hex, arrays and tuples as lists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..hashes import keccak256

__all__ = [
    "abi_decode",
    "abi_encode",
    "decode_function_call",
    "encode_function_call",
    "encode_with_selector",
    "event_topic",
    "function_selector",
    "parse_signature",
]


@dataclass(frozen=True)
class _T:
    kind: str
    bits: int = 0
    size: int = 0
    of: tuple[_T, ...] = ()
    length: int | None = None


def _split(s: str) -> list[str]:
    if s == "":
        return []
    out, depth, start = [], 0, 0
    for i, c in enumerate(s):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
        if depth < 0:
            raise ValueError(f"unbalanced parentheses in {s}")
    if depth != 0:
        raise ValueError(f"unbalanced parentheses in {s}")
    out.append(s[start:])
    return out


def _parse(raw: str) -> _T:
    t = raw.strip()
    m = re.fullmatch(r"(.*)\[(\d*)\]", t)
    if m:
        of = _parse(m.group(1))
        if m.group(2) == "":
            return _T("array", of=(of,))
        n = int(m.group(2))
        if n <= 0:
            raise ValueError(f"bad array length in {t}")
        return _T("array", of=(of,), length=n)
    if t.startswith("(") and t.endswith(")"):
        return _T("tuple", of=tuple(_parse(x) for x in _split(t[1:-1])))
    if t in ("address", "bool", "bytes", "string"):
        return _T(t)
    m = re.fullmatch(r"(u?int)(\d*)", t)
    if m:
        bits = 256 if m.group(2) == "" else int(m.group(2))
        if bits < 8 or bits > 256 or bits % 8:
            raise ValueError(f"bad integer width in {t}")
        return _T(m.group(1), bits=bits)
    m = re.fullmatch(r"bytes(\d+)", t)
    if m:
        size = int(m.group(1))
        if not 1 <= size <= 32:
            raise ValueError(f"bad byte width in {t}")
        return _T("fixed", size=size)
    raise ValueError(f"unsupported ABI type: {t}")


def _canonical(t: _T) -> str:
    if t.kind in ("uint", "int"):
        return f"{t.kind}{t.bits}"
    if t.kind == "fixed":
        return f"bytes{t.size}"
    if t.kind == "array":
        return f"{_canonical(t.of[0])}[{'' if t.length is None else t.length}]"
    if t.kind == "tuple":
        return "(" + ",".join(_canonical(x) for x in t.of) + ")"
    return t.kind


def _dynamic(t: _T) -> bool:
    if t.kind in ("bytes", "string"):
        return True
    if t.kind == "array":
        return t.length is None or _dynamic(t.of[0])
    if t.kind == "tuple":
        return any(_dynamic(x) for x in t.of)
    return False


def _head(t: _T) -> int:
    if _dynamic(t):
        return 32
    if t.kind == "array":
        return t.length * _head(t.of[0])  # type: ignore[operator]
    if t.kind == "tuple":
        return sum(_head(x) for x in t.of)
    return 32


def _bytes(v: Any, what: str) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str) and re.fullmatch(r"0x([0-9a-fA-F]{2})*", v):
        return bytes.fromhex(v[2:])
    raise ValueError(f"{what} must be bytes or 0x hex")


def _int(v: Any, what: str) -> int:
    if isinstance(v, bool):
        raise ValueError(f"{what} must be an integer")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and re.fullmatch(r"-?\d+|0x[0-9a-fA-F]+", v):
        return int(v, 0) if v.startswith("0x") else int(v)
    raise ValueError(f"{what} must be an integer")


def _word(n: int) -> bytes:
    return (n % (1 << 256)).to_bytes(32, "big")


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 32)


def _seq(types: list[_T], values: list[Any]) -> bytes:
    if len(types) != len(values):
        raise ValueError(f"expected {len(types)} values, got {len(values)}")
    heads, tails = [], []
    offset = sum(_head(t) for t in types)
    for t, v in zip(types, values):
        e = _one(t, v)
        if _dynamic(t):
            heads.append(_word(offset))
            tails.append(e)
            offset += len(e)
        else:
            heads.append(e)
    return b"".join(heads + tails)


def _one(t: _T, v: Any) -> bytes:
    what = _canonical(t)
    if t.kind == "uint":
        n = _int(v, what)
        if not 0 <= n < 1 << t.bits:
            raise ValueError(f"{what}: {n} out of range")
        return _word(n)
    if t.kind == "int":
        n = _int(v, what)
        lim = 1 << (t.bits - 1)
        if not -lim <= n < lim:
            raise ValueError(f"{what}: {n} out of range")
        return _word(n)
    if t.kind == "address":
        b = _bytes(v, what)
        if len(b) != 20:
            raise ValueError("address must be 20 bytes")
        return b"\x00" * 12 + b
    if t.kind == "bool":
        if not isinstance(v, bool):
            raise ValueError("bool must be True or False")
        return _word(int(v))
    if t.kind == "fixed":
        b = _bytes(v, what)
        if len(b) != t.size:
            raise ValueError(f"{what} must be {t.size} bytes")
        return _pad(b)
    if t.kind in ("bytes", "string"):
        if t.kind == "string":
            if not isinstance(v, str):
                raise ValueError("string must be a str")
            b = v.encode()
        else:
            b = _bytes(v, what)
        return _word(len(b)) + _pad(b)
    if t.kind == "array":
        if not isinstance(v, (list, tuple)):
            raise ValueError(f"{what} must be a list")
        if t.length is not None and len(v) != t.length:
            raise ValueError(f"{what} must hold {t.length} values")
        body = _seq([t.of[0]] * len(v), list(v))
        return body if t.length is not None else _word(len(v)) + body
    if not isinstance(v, (list, tuple)):
        raise ValueError(f"{what} must be a list of its fields")
    return _seq(list(t.of), list(v))


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def word(self, at: int) -> bytes:
        if at < 0 or at + 32 > len(self.data):
            raise ValueError(f"ABI data ends before byte {at + 32}")
        return self.data[at : at + 32]

    def uint(self, at: int) -> int:
        return int.from_bytes(self.word(at), "big")

    def size(self, at: int) -> int:
        n = self.uint(at)
        if n > len(self.data):
            raise ValueError(f"ABI length or offset {n} beyond the data")
        return n


def _dseq(r: _Reader, types: list[_T], base: int) -> list[Any]:
    out, at = [], base
    for t in types:
        out.append(_done(r, t, base + r.size(at)) if _dynamic(t) else _done(r, t, at))
        at += _head(t)
    return out


def _done(r: _Reader, t: _T, at: int) -> Any:
    what = _canonical(t)
    if t.kind == "uint":
        n = r.uint(at)
        if n >= 1 << t.bits:
            raise ValueError(f"{what} out of range")
        return n
    if t.kind == "int":
        n = r.uint(at)
        if n >= 1 << 255:
            n -= 1 << 256
        lim = 1 << (t.bits - 1)
        if not -lim <= n < lim:
            raise ValueError(f"{what} out of range")
        return n
    if t.kind == "address":
        w = r.word(at)
        if any(w[:12]):
            raise ValueError("address has non-zero high bytes")
        return "0x" + w[12:].hex()
    if t.kind == "bool":
        n = r.uint(at)
        if n > 1:
            raise ValueError("bool is neither 0 nor 1")
        return n == 1
    if t.kind == "fixed":
        w = r.word(at)
        if any(w[t.size :]):
            raise ValueError(f"{what} has non-zero padding")
        return "0x" + w[: t.size].hex()
    if t.kind in ("bytes", "string"):
        n = r.size(at)
        if at + 32 + n > len(r.data):
            raise ValueError(f"{what} runs past the data")
        b = r.data[at + 32 : at + 32 + n]
        return "0x" + b.hex() if t.kind == "bytes" else b.decode("utf-8")
    if t.kind == "array":
        if t.length is not None:
            return _dseq(r, [t.of[0]] * t.length, at)
        n = r.size(at)
        if n * _head(t.of[0]) > len(r.data):
            raise ValueError(f"{what} length beyond the data")
        return _dseq(r, [t.of[0]] * n, at + 32)
    return _dseq(r, list(t.of), at)


def abi_encode(types: list[str], values: list[Any]) -> bytes:
    """Encode ``values`` as the ABI encodes a function's arguments of ``types``."""
    return _seq([_parse(t) for t in types], list(values))


def abi_decode(types: list[str], data: bytes | str) -> list[Any]:
    """Decode return data, log data, or calldata after its selector as values of ``types``."""
    b = _bytes(data, "data") if isinstance(data, str) else bytes(data)
    return _dseq(_Reader(b), [_parse(t) for t in types], 0)


def parse_signature(signature: str) -> tuple[str, list[str], str]:
    """``name(type1,type2)`` as its name, normalized argument types and canonical form."""
    m = re.fullmatch(r"\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\((.*)\)\s*", signature)
    if not m:
        raise ValueError(f"not a function signature: {signature}")
    types = [_canonical(_parse(x)) for x in _split(re.sub(r"\s+", "", m.group(2)))]
    return m.group(1), types, f"{m.group(1)}({','.join(types)})"


def function_selector(signature: str) -> bytes:
    """The 4-byte selector of a function signature."""
    return keccak256(parse_signature(signature)[2].encode())[:4]


def event_topic(signature: str) -> str:
    """An event signature's topic 0, as ``0x`` hex."""
    return "0x" + keccak256(parse_signature(signature)[2].encode()).hex()


def encode_function_call(signature: str, values: list[Any]) -> bytes:
    """Calldata for ``signature`` called with ``values``."""
    return function_selector(signature) + abi_encode(parse_signature(signature)[1], values)


def encode_with_selector(selector: bytes | str, types: list[str], values: list[Any]) -> bytes:
    """Calldata for a fixed 4-byte selector with arguments of ``types``."""
    sel = _bytes(selector, "selector")
    if len(sel) != 4:
        raise ValueError("a selector is 4 bytes")
    return sel + abi_encode(types, values)


def decode_function_call(types: list[str], calldata: bytes | str) -> tuple[str, list[Any]]:
    """Calldata split into its selector (``0x`` hex) and decoded arguments."""
    b = _bytes(calldata, "calldata") if isinstance(calldata, str) else bytes(calldata)
    if len(b) < 4:
        raise ValueError("calldata is shorter than a selector")
    return "0x" + b[:4].hex(), abi_decode(types, b[4:])
