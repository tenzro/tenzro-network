# Verify your download

Every Tenzro release is a set of archives plus a manifest of their SHA-256 digests, and the manifest
is signed. Check both before you unpack or install anything.

## What a release contains

| File | What it is |
|---|---|
| `tenzro-node-<platform>-<variant>.tar.gz` or `.zip` | the archive you install |
| `SHA256SUMS` | one line per archive: its SHA-256 digest and name |
| `SHA256SUMS.sig` | a cosign signature over `SHA256SUMS` |
| `<archive>.sig` | a cosign signature over that archive |
| `tenzro-release.pub` | the public key that verifies the signatures |
| `matrix.json` | how each archive was built: commit, toolchain, features, lockfile digest |
| `sbom-<commit>.spdx.json`, `provenance-<commit>.intoto.json` | the software bill of materials and the build provenance statement |
| `provenance-<commit>.dsse.json` | the provenance statement, signed with the release key |

## Steps on Linux and macOS

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.x, then in the folder
where you downloaded the release:

```bash
# 1. The manifest is signed by the release key.
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS

# 2. Your archive matches the manifest (macOS: shasum -a 256 -c ...).
sha256sum -c SHA256SUMS --ignore-missing
```

On Linux the installer in the archive (`tenzro-node-install`) runs the same checks before it
unpacks anything: `tenzro-node-install --sums SHA256SUMS --sig SHA256SUMS.sig --key tenzro-release.pub
tenzro-node-linux-x86_64-cpu.tar.gz`. It refuses an archive that `SHA256SUMS` does not list, lists
with another hash, or whose manifest signature does not verify. It needs cosign for the signature.

The release signature is made with a hardware-held key and is not uploaded to a transparency log, so `--insecure-ignore-tlog=true` is required: without it cosign 3 looks for a log entry and fails with "signature not found in transparency log". The check against the public key is complete without the log. Step 1 prints `Verified OK`. Step 2 prints `<archive>: OK` for each archive you downloaded. If either
step prints anything else, delete the download and do not install it. To check a single archive
against its own signature, run `cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature <archive>.sig <archive>`.

## Steps on Windows

In PowerShell, with cosign installed:

```powershell
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
(Get-FileHash -Algorithm SHA256 .\tenzro-node-windows-x86_64-cuda.zip).Hash
```

Compare the printed hash, ignoring case, with the line for that archive in `SHA256SUMS`.

## Where the public key lives

The release signing key is held in hardware (a PKCS#11 token) by the release signer; the private
key never leaves it and is never on a build machine (`scripts/supply-chain/release.sh` refuses a
key file). The public half is exported from that token with `cosign public-key` and published as
`tenzro-release.pub` in each release next to the manifest.

Status, stated plainly: the repository does not yet record the key's fingerprint or a second
publication channel for it. A key that arrives in the same place as the archive proves the archive
was not corrupted and was signed by whoever holds that key; it does not protect you if the release
page itself were replaced. Until a fingerprint is published somewhere independent of the release
page, treat the SHA-256 digest in the release notes as a second reference and compare it with the
line in `SHA256SUMS`. Once you have verified one release, keep that copy of `tenzro-release.pub` and
check later releases against your kept copy; a changed key is a reason to stop and ask.

## Windows code signing

The Windows archives and the Windows control app are not Authenticode-signed unless the build
machine was configured with a code-signing certificate (`bundle.windows.certificateThumbprint`; see
`scripts/release/build-control-windows.ps1`). A release that was not so configured will make
Windows SmartScreen warn about an unknown publisher. That warning is expected for an unsigned build
and is not a verdict on the archive: the cosign signature and the SHA-256 check above are the
verification. The macOS app is checked with `codesign --verify --deep --strict` at build time.

## Rebuilding to compare

`matrix.json` records the commit, toolchain, features and lockfile digest of each archive.
`scripts/supply-chain/reproduce.sh` rebuilds a release from that commit so the digest can be
compared with the published one; see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).
