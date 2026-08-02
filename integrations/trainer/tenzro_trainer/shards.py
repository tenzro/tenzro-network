"""Shard URI resolution.

The native scheme is ``tenzro://`` — content-addressed blobs served by the
local node's iroh blob store, fetched over JSON-RPC
(``tenzro_iroh_fetchBlob``) and BLAKE3-verified on transfer by the node.
``ipfs://`` and ``ar://`` are supported alternatives resolved through HTTP
gateways, and plain ``http(s)://`` URLs download directly. ``file://`` and
bare paths pass through untouched (Confidential-tier shards arrive
pre-decrypted as ``file://`` pointers into an enclave-private tmpfs; see
:mod:`tenzro_trainer.confidential`).

Remote fetches are cached under ``$TENZRO_TRAINER_CACHE/shards`` (default
``~/.cache/tenzro-trainer/shards``) keyed by the SHA-256 of the URI, so
repeated rounds over the same shard hit the network once.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import os
import tarfile
import tempfile
from pathlib import Path

import requests

log = logging.getLogger(__name__)

_REMOTE_SCHEMES = ("tenzro://", "ipfs://", "ar://", "https://", "http://")


def _tenzro_home() -> Path:
    """The one Tenzro root: ``$TENZRO_HOME``, else ``~/.tenzro``.

    Mirrors ``tenzro_types::paths::tenzro_home`` on the Rust side. The node
    exports ``TENZRO_HOME`` when it spawns this trainer, so a trainer launched
    by a node lands in the same place as everything else that node owns; a
    trainer run by hand still agrees with it by construction.
    """
    root = os.environ.get("TENZRO_HOME", "").strip()
    if root:
        return Path(root).expanduser()
    return Path.home() / ".tenzro"


def _cache_dir() -> Path:
    """Shared dataset-shard cache.

    Shared across every trainer on the machine, deliberately: shards are
    keyed by digest, so two trainers pulling the same dataset deduplicate for
    free. ``TENZRO_TRAINER_CACHE`` still overrides for operators keeping
    datasets on a separate volume.
    """
    override = os.environ.get("TENZRO_TRAINER_CACHE", "").strip()
    root = Path(override).expanduser() if override else _tenzro_home() / "trainer-cache"
    return root / "shards"


def _cache_path(shard_uri: str) -> Path:
    digest = hashlib.sha256(shard_uri.encode("utf-8")).hexdigest()[:32]
    return _cache_dir() / digest


def _atomic_write(dest: Path, payload: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=dest.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _fetch_tenzro(shard_uri: str) -> bytes:
    """Fetch a ``tenzro://`` blob through the local node's JSON-RPC."""
    rpc_url = os.environ.get("TENZRO_RPC_URL", "http://127.0.0.1:8545")
    timeout = float(os.environ.get("TENZRO_SHARD_TIMEOUT_SECS", "600"))
    resp = requests.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tenzro_iroh_fetchBlob",
            "params": {"tenzro_uri": shard_uri},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("error"):
        err = body["error"]
        raise RuntimeError(
            f"node could not fetch {shard_uri}: "
            f"{err.get('message', err)} (code {err.get('code', '?')})"
        )
    result = body.get("result") or {}
    b64 = result.get("bytes_b64")
    if not isinstance(b64, str):
        # noqa-worthy on TRY004: a malformed response from the node is a
        # protocol failure, not the caller passing the wrong type.
        raise RuntimeError(  # noqa: TRY004
            f"malformed tenzro_iroh_fetchBlob result for {shard_uri}"
        )
    return base64.b64decode(b64)


def gateway_url(shard_uri: str) -> str:
    """Map an ``ipfs://`` / ``ar://`` URI to its HTTP gateway URL.

    ``http(s)://`` URLs are returned unchanged. Gateways are overridable via
    ``TENZRO_IPFS_GATEWAY`` / ``TENZRO_ARWEAVE_GATEWAY``.
    """
    if shard_uri.startswith("ipfs://"):
        gw = os.environ.get("TENZRO_IPFS_GATEWAY", "https://ipfs.io/ipfs")
        return gw.rstrip("/") + "/" + shard_uri[len("ipfs://") :]
    if shard_uri.startswith("ar://"):
        gw = os.environ.get("TENZRO_ARWEAVE_GATEWAY", "https://arweave.net")
        return gw.rstrip("/") + "/" + shard_uri[len("ar://") :]
    return shard_uri


def _fetch_http(url: str) -> bytes:
    timeout = float(os.environ.get("TENZRO_SHARD_TIMEOUT_SECS", "600"))
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.content


def _extract_dir(archive: Path) -> Path:
    """Unpack a tar shard (vision ImageFolder layout) next to its cache file."""
    dest = archive.with_name(archive.name + ".d")
    if dest.is_dir():
        return dest
    tmp = archive.with_name(archive.name + ".d.tmp")
    with tarfile.open(archive) as tar:
        tar.extractall(tmp, filter="data")
    os.replace(tmp, dest)
    return dest


def resolve_shard(shard_uri: str, *, extract: bool = False) -> Path:
    """Resolve a shard URI to a local filesystem path.

    * ``file://`` and bare paths pass through.
    * ``tenzro://`` fetches from the local node's iroh blob store.
    * ``ipfs://`` / ``ar://`` fetch through HTTP gateways.
    * ``http(s)://`` downloads directly.

    With ``extract=True``, a fetched tar archive is unpacked and the
    directory returned — the vision adapter's ImageFolder shards travel as
    tarballs over content-addressed schemes.
    """
    if shard_uri.startswith("file://"):
        return Path(shard_uri[len("file://") :])
    if not shard_uri.startswith(_REMOTE_SCHEMES):
        return Path(shard_uri)

    cached = _cache_path(shard_uri)
    if not cached.is_file():
        if shard_uri.startswith("tenzro://"):
            payload = _fetch_tenzro(shard_uri)
        else:
            payload = _fetch_http(gateway_url(shard_uri))
        _atomic_write(cached, payload)
        log.info("fetched shard %s: %d bytes -> %s", shard_uri, len(payload), cached)
    else:
        log.info("shard cache hit: %s -> %s", shard_uri, cached)

    if extract and tarfile.is_tarfile(cached):
        return _extract_dir(cached)
    return cached
