"""Tests for the shard URI resolver."""

from __future__ import annotations

import base64
import io
import tarfile

import pytest

from tenzro_trainer import shards
from tenzro_trainer.shards import gateway_url, resolve_shard


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("TENZRO_TRAINER_CACHE", str(tmp_path / "cache"))


# ---------------------------------------------------------------------------
# Passthrough schemes
# ---------------------------------------------------------------------------


def test_file_uri_passthrough(tmp_path):
    p = tmp_path / "shard.jsonl"
    p.write_bytes(b"hello")
    assert resolve_shard(f"file://{p}") == p


def test_bare_path_passthrough(tmp_path):
    p = tmp_path / "shard.parquet"
    p.write_bytes(b"x")
    assert resolve_shard(str(p)) == p


# ---------------------------------------------------------------------------
# Gateway URL mapping
# ---------------------------------------------------------------------------


def test_ipfs_gateway_default():
    assert gateway_url("ipfs://QmAbC/shard-3.parquet") == (
        "https://ipfs.io/ipfs/QmAbC/shard-3.parquet"
    )


def test_ipfs_gateway_override(monkeypatch):
    monkeypatch.setenv("TENZRO_IPFS_GATEWAY", "https://gw.example/ipfs/")
    assert gateway_url("ipfs://QmAbC") == "https://gw.example/ipfs/QmAbC"


def test_arweave_gateway_default():
    assert gateway_url("ar://TXID") == "https://arweave.net/TXID"


def test_https_url_unchanged():
    assert gateway_url("https://host/x") == "https://host/x"


# ---------------------------------------------------------------------------
# tenzro:// via the local node RPC
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


def test_tenzro_fetch_decodes_and_caches(monkeypatch):
    payload = b"training bytes"
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append((url, json["method"], json["params"]))
        return _Resp(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tenzro_uri": json["params"]["tenzro_uri"],
                    "size_bytes": len(payload),
                    "bytes_b64": base64.b64encode(payload).decode(),
                },
            }
        )

    monkeypatch.setattr(shards.requests, "post", fake_post)
    monkeypatch.setenv("TENZRO_RPC_URL", "http://127.0.0.1:8545")

    uri = "tenzro://blob/" + "ab" * 32
    path = resolve_shard(uri)
    assert path.read_bytes() == payload
    assert calls == [
        ("http://127.0.0.1:8545", "tenzro_iroh_fetchBlob", {"tenzro_uri": uri})
    ]

    # Second resolve is a cache hit — no further RPC.
    assert resolve_shard(uri) == path
    assert len(calls) == 1


def test_tenzro_fetch_surfaces_node_error(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return _Resp(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "blob not found"},
            }
        )

    monkeypatch.setattr(shards.requests, "post", fake_post)
    with pytest.raises(RuntimeError, match="blob not found"):
        resolve_shard("tenzro://blob/" + "cd" * 32)


# ---------------------------------------------------------------------------
# Gateway fetch + tar extraction (vision ImageFolder shards)
# ---------------------------------------------------------------------------


def _tarball(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_http_fetch_with_extract(monkeypatch):
    archive = _tarball({"cats/a.png": b"png1", "dogs/b.png": b"png2"})

    class _Get:
        def __init__(self):
            self.content = archive

        def raise_for_status(self):
            pass

    monkeypatch.setattr(shards.requests, "get", lambda url, timeout=None: _Get())

    root = resolve_shard("https://host/shard.tar", extract=True)
    assert root.is_dir()
    assert (root / "cats" / "a.png").read_bytes() == b"png1"
    assert (root / "dogs" / "b.png").read_bytes() == b"png2"

    # Re-resolve reuses the extracted directory.
    assert resolve_shard("https://host/shard.tar", extract=True) == root


def test_extract_false_returns_archive_file(monkeypatch):
    archive = _tarball({"x": b"1"})

    class _Get:
        def __init__(self):
            self.content = archive

        def raise_for_status(self):
            pass

    monkeypatch.setattr(shards.requests, "get", lambda url, timeout=None: _Get())
    path = resolve_shard("https://host/other.tar")
    assert path.is_file()
    assert path.read_bytes() == archive
