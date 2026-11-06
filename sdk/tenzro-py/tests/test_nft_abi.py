"""ABI encoding against the Solidity specification's examples, and the NFT
factory calldata and return decoding against sdk/fixtures/nft, the vectors
the VM test runs through the precompile."""

import json
import re
from pathlib import Path

import pytest

from tenzro.chain import (
    NFT_FACTORY_ADDRESS,
    NFT_SELECTORS,
    NFT_TRANSFER_TOPIC,
    NftClient,
    abi_decode,
    abi_encode,
    decode_function_call,
    decode_nft_transfer,
    encode_function_call,
    event_topic,
    function_selector,
    nft_calldata,
    nft_collection_id,
    nft_decode,
    nft_transaction,
    parse_signature,
)
from tenzro.typed_tx import tx_type

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "sdk" / "fixtures"
ABI = json.loads((FIX / "abi" / "vectors.json").read_text(encoding="utf-8"))
NFT = json.loads((FIX / "nft" / "vectors.json").read_text(encoding="utf-8"))


def _norm(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return v


def test_the_specifications_calls_encode_and_decode_exactly():
    for c in ABI["cases"]:
        assert "0x" + function_selector(c["signature"]).hex() == c["selector"]
        assert "0x" + encode_function_call(c["signature"], c["values"]).hex() == c["calldata"]
        _, types, _ = parse_signature(c["signature"])
        sel, args = decode_function_call(types, c["calldata"])
        assert sel == c["selector"]
        assert _norm(args) == c["values"]


def test_signed_integers_tuples_and_fixed_arrays_round_trip():
    types = ["int8", "int256", "(address,bool,string)", "uint16[2]", "(uint8,bytes)[]"]
    values = [-1, -(2**200), ["0x" + "11" * 20, True, "x"], [1, 65535], [[7, "0x"], [8, "0xabcd"]]]
    assert abi_decode(types, abi_encode(types, values)) == values
    assert parse_signature("transfer(address, uint)")[2] == "transfer(address,uint256)"
    assert function_selector("transfer(address,uint256)").hex() == "a9059cbb"
    assert event_topic("Transfer(address,address,uint256)") == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@pytest.mark.parametrize(
    "types,values,match",
    [
        (["uint8"], [256], "out of range"),
        (["int8"], [-129], "out of range"),
        (["address"], ["0x1234"], "20 bytes"),
        (["bytes2"], ["0x010203"], "2 bytes"),
        (["bool"], [1], "True or False"),
    ],
)
def test_out_of_range_values_are_refused(types, values, match):
    with pytest.raises(ValueError, match=match):
        abi_encode(types, values)


def test_malformed_data_is_refused():
    with pytest.raises(ValueError, match="neither 0 nor 1"):
        abi_decode(["bool"], "0x" + "00" * 31 + "02")
    with pytest.raises(ValueError, match="high bytes"):
        abi_decode(["address"], "0x" + "ff" * 32)
    with pytest.raises(ValueError, match="ends before"):
        abi_decode(["uint256"], "0x" + "00" * 31)
    with pytest.raises(ValueError, match="out of range"):
        abi_decode(["uint8"], "0x" + "00" * 30 + "0100")


_CALLS = {
    "createCollection": "create_collection",
    "getCollection": "get_collection",
    "mint": "mint",
    "mintBatch": "mint_batch",
    "transfer": "transfer",
    "ownerOf": "owner_of",
    "balanceOf": "balance_of",
    "tokenUri": "token_uri",
    "registerEvmPointer": "register_evm_pointer",
    "mintMulti": "mint_multi",
    "balanceOfMulti": "balance_of_multi",
}

_DECODE = {
    "createCollection": nft_decode.id,
    "mint": nft_decode.bool,
    "mintBatch": lambda d: str(nft_decode.uint(d)),
    "transfer": nft_decode.bool,
    "registerEvmPointer": nft_decode.bool,
    "mintMulti": nft_decode.bool,
    "ownerOf": nft_decode.address,
    "balanceOf": lambda d: str(nft_decode.uint(d)),
    "balanceOfMulti": lambda d: str(nft_decode.uint(d)),
    "tokenUri": nft_decode.string,
    "getCollection": lambda d: (lambda c: {
        "name": c.name, "symbol": c.symbol, "creator": c.creator, "totalSupply": str(c.total_supply), "standard": c.standard,
    })(nft_decode.collection(d)),
}


def _args(a):
    return [int(x) if isinstance(x, str) and x.isdigit() else _args(x) if isinstance(x, list) else x for x in a]


def test_nft_calldata_returns_and_logs_match_the_vectors():
    assert NFT["factory"] == NFT_FACTORY_ADDRESS
    assert NFT["transfer_topic"] == NFT_TRANSFER_TOPIC
    assert NFT["selectors"] == NFT_SELECTORS
    for c in NFT["collection_ids"]:
        assert nft_collection_id(c["creator"], c["nonce"]) == c["id"]
    for s in NFT["steps"]:
        got = getattr(nft_calldata, _CALLS[s["call"]])(*_args(s["args"]))
        assert "0x" + got.hex() == s["calldata"], s["call"]
        if s["output"] is not None and "decoded" in s:
            assert _DECODE[s["call"]](s["output"]) == s["decoded"], s["call"]
        for log in s.get("logs", []):
            t = decode_nft_transfer({"address": NFT["factory"], **log})
            assert t is not None and t.collection_id == log["topics"][1] and t.token_id == int(log["data"], 16)
    id1, id2 = NFT["collection_ids"][0]["id"], NFT["collection_ids"][1]["id"]
    assert "0x" + nft_calldata.mint_random(id1, NFT["accounts"]["bob"], 100).hex() == NFT["random"]["mint_random"]
    assert "0x" + nft_calldata.fulfill_random("0x" + "ee" * 32).hex() == NFT["random"]["fulfill_random"]
    assert "0x" + nft_calldata.register_svm_pointer(id2, "0x" + "5a" * 32).hex() == NFT["random"]["register_svm_pointer"]
    assert decode_nft_transfer({"topics": ["0x" + "00" * 32], "data": "0x"}) is None


def test_the_selectors_are_the_factorys():
    src = (ROOT / "crates" / "tenzro-vm" / "src" / "evm" / "nft_factory.rs").read_text(encoding="utf-8")
    table = dict(
        (name, "0x" + sel) for sel, name in re.findall(r"^//! \| 0x([0-9a-f]{8}) \| ([A-Za-z]+)\(", src, re.M)
    )
    assert table == NFT_SELECTORS


def test_nft_inputs_the_factory_would_refuse_are_refused_before_signing():
    id1, bob = NFT["collection_ids"][0]["id"], NFT["accounts"]["bob"]
    with pytest.raises(ValueError, match="zero address"):
        nft_calldata.mint(id1, "0x" + "00" * 20, 1)
    with pytest.raises(ValueError, match="128 bits"):
        nft_calldata.mint(id1, bob, 2**128)
    with pytest.raises(ValueError, match="512 bytes"):
        nft_calldata.mint(id1, bob, 1, "x" * 513)
    with pytest.raises(ValueError, match="1 to 256"):
        nft_calldata.mint_batch(id1, bob, [])
    with pytest.raises(ValueError, match="positive"):
        nft_calldata.mint_multi(id1, bob, 1, 0)


def test_writes_are_one_contract_call_and_reads_go_through_eth_call():
    id1 = NFT["collection_ids"][0]["id"]
    tx = nft_transaction(nft_calldata.mint(id1, NFT["accounts"]["bob"], 1), nft_calldata.transfer(id1, NFT["accounts"]["alice"], 1))
    assert tx.kind == "ContractCall"
    assert len(tx.fields["calls"]) == 2
    assert tx.fields["calls"][0]["to"] == [0] * 18 + [0x10, 0x06]
    assert tx_type(tx) == {"ContractCall": tx.fields}
    out = next(s["output"] for s in NFT["steps"] if s["call"] == "getCollection")
    seen = []

    class Rpc:
        def call(self, method, params=None):
            seen.append((method, params))
            return out

    assert NftClient(Rpc()).collection(id1).name == "Tenzro Cats"
    assert seen[0] == ("eth_call", [{"to": NFT_FACTORY_ADDRESS, "data": "0x" + nft_calldata.get_collection(id1).hex()}, "latest"])
