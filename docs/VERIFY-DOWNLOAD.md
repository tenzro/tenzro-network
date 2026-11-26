# Verify your download

Every Tenzro release is a set of archives plus a manifest of their SHA-256 digests, and the manifest
is signed. Check both before you unpack or install anything.

## What a release contains

| File | What it is |
|---|---|
| `tenzro-node-<platform>-<variant>.tar.gz` or `.zip` | the archive you install; it carries Tenzro Control, the desktop app, in `control/` |
| `tenzro-<version>-windows-x86_64-cuda.msi`, `tenzro-<version>-macos.pkg`, `tenzro-cpu`, `tenzro-cuda` and `tenzro-control` `.deb` and `.rpm` | the installers, each made from the exact bytes of one archive |
| `packages.json` | for each installer, the archive it was made from and that archive's digest |
| `SHA256SUMS` | one line per archive and per installer: its SHA-256 digest and name |
| `SHA256SUMS.sig` | a cosign signature over `SHA256SUMS` |
| `tenzro-release.pub` | the public key that verifies the signatures |
| `matrix.json` | how each archive was built: commit, toolchain, features, lockfile digest |
| `sbom-<commit>.spdx.json`, `provenance-<commit>.intoto.json` | the software bill of materials and the build provenance statement (unsigned; the signed object is `SHA256SUMS`) |

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
step prints anything else, delete the download and do not install it.

The signature is a classical ECDSA P-256 signature from a hardware-held key. No quantum resistance is claimed. Archives have no signature of their own: `SHA256SUMS` is the signed object, and each archive is checked against it.


## Steps on Windows

In PowerShell, with cosign installed:

```powershell
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
(Get-FileHash -Algorithm SHA256 .\tenzro-node-windows-x86_64-cuda.zip).Hash
```

Compare the printed hash, ignoring case, with the line for that archive in `SHA256SUMS`.

## The Assistant's guides and model

The guides the Assistant answers from are compiled into the `tenzro` binary, so the
archive's digest in the signed `SHA256SUMS` covers them; a release has no separate
pack to fetch or check. The Assistant's model is not in the release. When you agree
to `/assistant` in the console, it is downloaded from the network's model catalog
and checked against the digests its catalog entry pins before it is served.

## Where the public key lives

The release signing key is a P-256 key created inside the TPM 2.0 of a Tenzro-operated machine. It is
non-exportable: the private key cannot leave the chip, is never on a build machine, and every use needs a
passphrase typed by the release signer. The signer reads `SHA256SUMS` line by line before typing it, and
signs only that manifest. The
public half is published as `tenzro-release.pub` in each release next to the manifest and in
[RELEASE-KEYS.md](RELEASE-KEYS.md).

Release key fingerprint (SHA-256 of the DER encoding of the public key):

```
c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d
```

Compute it from the file you downloaded and compare it with the line above, with the same line in
[RELEASE-KEYS.md](RELEASE-KEYS.md) in the public repository, with
<https://tenzro.com/docs/verify-your-download> and with
<https://downloads.tenzro.com/RELEASE-KEY.txt>:

```bash
openssl pkey -pubin -in tenzro-release.pub -outform DER | sha256sum
```

A key that arrives only in the same place as the archive proves the archive was not corrupted and was
signed by whoever holds that key; it does not protect you if that one place were replaced. That is why the
fingerprint is published in several places that do not share a server. If they do not agree, stop and ask.
Once you have verified one release, keep that copy of `tenzro-release.pub` and check later releases against
your kept copy; a changed key is a reason to stop and ask. [SIGNING-LOG.md](SIGNING-LOG.md) lists each
manifest the key has signed.

## Installers and Tenzro Control

An installer is checked exactly like an archive: its line in the signed `SHA256SUMS` must match
(`sha256sum -c --ignore-missing SHA256SUMS` on Linux, `shasum -a 256 -c --ignore-missing SHA256SUMS`
on macOS, the PowerShell steps above on Windows). The Windows and macOS installers put Tenzro
Control beside the node and open it when they finish; on Linux it is the separate
`tenzro-control` package, so a machine without a desktop never installs it. `packages.json` names
the archive each installer repackages, so you can check that the programs it installs are the
ones in that archive.

## Code signing

The Windows programs and installer carry an Authenticode signature, and the macOS programs, Tenzro
Control and the installer a Developer ID signature with notarisation, only when the release was
built with those certificates. Without them Windows SmartScreen warns about an unknown publisher
and macOS asks you to confirm opening an app from an unidentified developer. That warning is
expected for an unsigned build and is not a verdict on the download: the cosign signature and the
SHA-256 check above are the verification.

## Rebuilding to compare

`matrix.json` records the commit, toolchain, features and lockfile digest of each archive.
`scripts/supply-chain/reproduce.sh` rebuilds a release from that commit so the digest can be
compared with the published one; see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).
