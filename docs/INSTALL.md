# Install Tenzro

Install it, run `tenzro`, done. The first run checks your machine, asks what you want to do (provide compute, run a
validator or try a local chain), sets up your keys, starts the node and shows the console. The
installer itself starts nothing: no service is installed or enabled, nothing joins the network, and no key is
created until you choose to in the first run.

Native packages are pre-release and unsigned (see "Unsigned installers" below).

## Easy path

| You use | Do this | Then |
|---|---|---|
| Windows 10 and 11 (x86-64), with an NVIDIA GPU | Open `tenzro-<version>-windows-x86_64-cuda.msi` | Open a new terminal and run `tenzro` |
| Windows 10 and 11 (x86-64), without one | Open `tenzro-<version>-windows-x86_64-cpu.msi` | Open a new terminal and run `tenzro` |
| macOS 14 and newer on Apple silicon | Open `tenzro-<version>-macos.pkg` | Open a new terminal and run `tenzro` |
| Linux | Run `curl -fsSL https://downloads.tenzro.com/install.sh \| sh` | Run `tenzro` |

Verified: the Windows MSI, the macOS package and the Linux arm64 install script (see
[GETTING-STARTED.md](GETTING-STARTED.md)). Linux `.deb` and `.rpm` packages are described below.

## Advanced and manual setup

Package details, verifying a download by hand, silent installs and the manual archive path.

| You use | Install | You get |
|---|---|---|
| Debian, Ubuntu | `tenzro-cpu_<version>_amd64.deb` or `tenzro-cuda_<version>_arm64.deb` | `tenzro`, `tenzro-node`, `tenzro-check` on your PATH |
| Fedora, RHEL and relatives | `tenzro-cpu-<version>.x86_64.rpm` or `tenzro-cuda-<version>.aarch64.rpm` | the same |
| Windows 10 and 11 (x86-64) | `tenzro-<version>-windows-x86_64-cuda.msi` (NVIDIA GPU) or `tenzro-<version>-windows-x86_64-cpu.msi` | the same, a Start Menu entry, an uninstaller |
| macOS 14 and newer, Apple silicon | `tenzro-<version>-macos.pkg` | the same, a launcher in Applications |

Every installer repackages the exact files of the signed release archive it names (the package
records that archive's SHA-256 and the release commit). Nothing is rebuilt. The package files are
listed in the release's signed `SHA256SUMS` next to the archives, so you verify them the same way.

### 1. Verify, then install

Verification is [docs/VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md). In short, in the folder holding the
download and the release's `SHA256SUMS`, `SHA256SUMS.sig` and `tenzro-release.pub`:

```bash
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing        # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

Do this first. The installers are not signed with an operating-system code-signing
certificate (see "Unsigned installers" below), so the release signature is what proves the file is ours.

#### Linux

```bash
# Debian, Ubuntu (24.04 or newer)
sudo apt install ./tenzro-cpu_0.2.2-1_amd64.deb

# Fedora (40 or newer), RHEL 10 and relatives
sudo dnf install ./tenzro-cpu-0.2.2-1.x86_64.rpm
```

Choose the variant that matches the machine:

* `tenzro-cpu` runs anywhere and serves models on the CPU.
* `tenzro-cuda` is for machines with an NVIDIA GPU. It needs the NVIDIA driver and the CUDA runtime
  libraries and cuDNN named in its description, which are not part of the package. If the machine cannot
  use it, the install still completes, the hardware check says `NOT READY`, says why, and tells you how to switch.

The two packages conflict and replace each other, so exactly one is installed. With apt, installing the
other one removes the first (`sudo apt install ./tenzro-cuda_...`). With dnf, use `sudo dnf swap tenzro-cpu tenzro-cuda`.
Your keys and data are not in the package and are never touched by installing, upgrading, swapping or removing it.

These builds need glibc 2.39 or newer (Ubuntu 24.04, Fedora 40, Debian 13). On an older system, such as Debian 12 or
RHEL 9, the package manager refuses the install and says which library is too old; nothing is changed.

What it installs:

| Path | What |
|---|---|
| `/usr/lib/tenzro/bin/tenzro`, `tenzro-node`, `tenzro-check` | the programs (the node resolves its ONNX Runtime libraries through `$ORIGIN/../lib`) |
| `/usr/lib/tenzro/lib/` | ONNX Runtime and its CUDA provider (CUDA package only) |
| `/usr/lib/tenzro/PACKAGE-INFO` | package, version, source archive and its SHA-256, release and public commits |
| `/usr/bin/tenzro`, `tenzro-node`, `tenzro-check` | links into `/usr/lib/tenzro/bin` |
| `/usr/bin/tenzro-node-install` | the archive's own installer, unchanged (installs an archive under `/usr/local`; you do not need it after a package install) |
| `/usr/share/doc/tenzro-cpu` (or `-cuda`) | licence, notice, first-run text |

At the end of the install the package manager shows the result of the hardware check, for example:

```text
Tenzro is installed. Nothing was started and nothing joined the network.

Tenzro hardware check (version 0.2.2-1)
  package build : cpu
  binary reports: build=CPU gpus=0 onnx=CPU startup=ok

READY: this is the CPU build and it runs on this machine.

Nothing is running and nothing has joined the network. The tenzro command is on your PATH.
Next step: run   tenzro setup   for the guided setup (roles, wallet, provider or validator, models),
or just   tenzro   for the interactive menu.
To remove Tenzro: use your package manager (sudo apt remove tenzro-cpu / tenzro-cuda, or sudo dnf remove ...).
```

Run `tenzro-check` again whenever you change the driver or the hardware. It is a check only.

Remove: `sudo apt remove tenzro-cpu` (or `purge`), `sudo dnf remove tenzro-cpu`. If you set up a
`tenzro-node` service later, removal tells you how to stop and remove that unit; it never stops a running node for you.

#### Windows

Double-click `tenzro-<version>-windows-x86_64-cuda.msi`, or from an elevated prompt:

```bat
msiexec /i tenzro-0.2.2-windows-x86_64-cuda.msi
```

The wizard shows a licence page, an install folder (default `C:\Program Files\Tenzro`), a choice of how to
add Tenzro to your PATH (for all users, for you only, or not at all), and a final page with a ticked box
"Run Tenzro setup now". Leave it ticked and a terminal window opens, runs the hardware check, and starts
`tenzro setup`. The Start Menu gets "Tenzro" (a terminal running `tenzro`), "Tenzro setup" and "Tenzro hardware check".

Silent install for scripts and fleets (no final page, nothing launched):

```bat
msiexec /i tenzro-0.2.2-windows-x86_64-cuda.msi /qn ADDTOPATH=system INSTALLFOLDER="C:\Tools\Tenzro"
```

`ADDTOPATH` is `system`, `user` or `none`. The MSI is per-machine, so it asks for administrator rights; it installs no service, and the hardware check runs only when you tick the final box, choose "Tenzro hardware check" or type `tenzro-check`, never during the install itself. Uninstall from "Apps > Installed apps >
Tenzro", or `msiexec /x tenzro-0.2.2-windows-x86_64-cuda.msi`; the PATH entry is removed with it. This is the CUDA
build and needs an NVIDIA GPU with a current driver; on a machine without one the hardware check says so and
tells you to use the command line only or another build. Language models need the CUDA 13 runtime libraries on
the machine, and ONNX models on the GPU need cuDNN 9 as well; neither is part of the installer. The installer
puts `DirectML.dll` and the ONNX Runtime provider libraries beside the programs and the network profile under
`share\network`; leave them where they are.

#### macOS

Open `tenzro-<version>-macos.pkg` and follow the installer, or:

```bash
sudo installer -pkg tenzro-0.2.2-macos.pkg -target /
```

The 0.2.2 package is for Apple silicon Macs (the Metal build) on macOS 14 and newer; macOS 27 runs on Apple silicon only. An Intel package (the CPU build, for Intel Macs on macOS 14 to 26) follows. It installs
into `/usr/local/lib/tenzro` with links in `/usr/local/bin`, plus a launcher called **Tenzro** in Applications. The
launcher opens Terminal, shows the hardware check and starts `tenzro setup`. macOS's installer has no "run after install"
checkbox, so the last page tells you to open that launcher or run `tenzro setup`.

On a Mac with a Secure Enclave the node keeps its identity keys there and they cannot be exported. A virtual
machine without a Secure Enclave runs a node, validators included, only with its
keys in another machine's TPM through a key holder
([NODE.md](NODE.md#raspberry-pi-and-other-edge-devices), which states the limits).

Remove: `sudo tenzro-uninstall`. It removes the programs, the launcher and the installer receipt; your keys and data are untouched.

### 2. First run

Whichever installer you used, the same three steps follow, in a terminal:

1. `tenzro-check` shows whether this machine can run the build you installed, in plain words, and what to do if not.
2. `tenzro setup` is the guided setup: your roles, your wallet, whether to provide compute or validate, and
   which models to use. Nothing is created before you confirm it. (`tenzro` alone opens the interactive menu.)
3. When you are ready, `tenzro setup` offers to install and start the node as a service (`--apply`). That is the first
   moment anything runs in the background, and it is your choice.

### 3. Manual, verified path (no installer)

Every release archive can still be used directly: verify it ([VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md)), unpack it, and
on Linux run `tenzro-node-install --sums SHA256SUMS --sig SHA256SUMS.sig --key tenzro-release.pub <archive>`, which
checks the archive against the signed manifest, refuses a build that does not match the machine, and installs under
`/usr/local`. On Windows and macOS, unpack the archive and put its `bin` directory on your PATH.

### 4. Unsigned installers

The installers are not signed with an operating-system code-signing certificate. What you will see, and why it is
safe to continue only after you verified the file as above:

* **Windows**: opening the MSI shows a User Account Control prompt that names the publisher as "Unknown publisher"
  instead of "Tenzro". A file downloaded with a browser also carries a web-origin mark, and Windows SmartScreen may
  show "Windows protected your PC": choose "More info", then "Run anyway". Neither prompt appears when you install
  with `msiexec` from a prompt on a file you copied locally.
* **macOS**: Gatekeeper refuses a package from an unidentified developer: "tenzro-0.2.2-macos.pkg cannot be opened
  because it is from an unidentified developer". Open System Settings > Privacy & Security and choose "Open Anyway", or
  Control-click the file and choose Open, or run `sudo installer -pkg ... -target /` (the installer command does not
  apply Gatekeeper), or remove the download mark with `xattr -d com.apple.quarantine <file>`.
* **Linux**: package managers check signatures of repositories, not of single files. `apt install ./file.deb` and
  `dnf install ./file.rpm` install a local file after you verified it; dnf may print "Package ... is not signed"
  only if you turn on its local-package signature check.

Signing the installers would need a Windows Authenticode certificate (an EV certificate or a cloud signing service) and
an Apple Developer ID Application and Installer certificate plus notarization. Those tie the installers' acceptance to
those vendors' accounts; Tenzro's own trust chain is the release signature above, and these certificates would only
remove the warnings.

## Signing and notarising the macOS package (maintainers)

`scripts/release/macos-release.sh` is the one wrapper for the Apple side, on a Mac:

- `doctor` lists which inputs are present (Xcode tools, the Developer ID Application and Installer certificates, the notary profile); it prints names only.
- `setup` finds or helps create the two certificates (the request is made locally and the private key goes into the login keychain), stores the notary credentials with `xcrun notarytool store-credentials` (it prompts; nothing secret passes through the script) and writes `TENZRO_MACOS_SIGN_IDENTITY`, `TENZRO_MACOS_INSTALLER_IDENTITY` and `TENZRO_MACOS_NOTARY_PROFILE` to `~/.config/tenzro/macos-release.env`, outside the repository.
- `release <other-arch-archive> [ref] [dist] [out]` runs `build-macos.sh` (Developer ID and hardened runtime), `build-pkg.sh` (sign, notarise, staple) and then `codesign --verify`, `pkgutil --check-signature`, `spctl -a -t install` and `stapler validate`; a failed check exits non-zero. Without credentials it ends at the unsigned package and lists what is missing (`--require-signed` makes that an error).

`TENZRO_MACOS_DRY_RUN=1` prints the commands instead of running them; `scripts/release/test_macos_release.sh` runs that on Linux. `TENZRO_MACOS_ENTITLEMENTS=<plist>` passes an entitlements file to codesign; none is passed by default.

### Shipping the node inside your own signed installer

Anyone can use `macos-release.sh` with their own `TENZRO_MACOS_*` identities: your Developer ID Application and Installer certificates and your notary profile, run through `setup`, then `release`. Tenzro signs and approves nothing, and you hold no keys: a user's keys are made in that Mac's Secure Enclave on first run and never leave it. The node does not check who signed it; a network's trust in a machine rests on its hardware key, never on the code-signing identity.

### The Secure Enclave key, unsigned or signed

The node keeps its device key in the Secure Enclave through CryptoKit, which hands back a wrapped key blob that the node stores in a file; it does not use the keychain, so it needs no provisioning profile and no entitlement (Apple: "There is no Secure Enclave entitlement"). That is why an unsigned node works, and an operator may run either way:

- **Unsigned (the binary Tenzro provides).** Best effort: on the systems tried the node creates its key on first start and reopens it on every start, but Apple documents no support for a Secure Enclave key from an unsigned program, so it may stop working on an OS update. If it cannot open its key it stops with an explicit error and never makes a new one.
- **Signed by a developer, the option operators can rely on.** A distribution from a developer such as Praecise, signed with their Developer ID (hardened runtime, no entitlements, as `macos-release.sh` does) and checked with the script below on a Mac before it ships. Each developer runs the check with their own identity; the result is theirs to publish.

Apple does not document whether the blob depends on who signed the binary, so the claim is checked, not assumed. `scripts/release/verify-enclave-signing.sh` runs on a Mac with a Secure Enclave (not a VM) and, for each pair of signing states (ad-hoc, and your Developer ID, in both orders), makes a key under the first, opens and signs with it, re-signs the binary as the second, and opens and signs again. It ends with `ENCLAVE SIGNING PASS` or `ENCLAVE SIGNING FAIL`. Run it with your identity before you ship a signed package.

Verified result: on 26 Nov 2026, on a MacBook Air (M2) with macOS 26.6.2, signed in at the desktop, all four pairs passed (unsigned to unsigned, unsigned to a Developer ID, a Developer ID to unsigned, and a Developer ID to the same one, hardened runtime, no entitlements): a key made under the first state opened and signed under the second. The check runs the key code in a test program built from the same crate as the node, not the shipped node binary, and it must run in the desktop session: over SSH the key creation and the signing both failed. Other macOS versions, Intel Macs and a node run as a launchd daemon have not been checked.

If a key blob cannot be opened (a different Mac, or a change the check would have caught), the node stops with an explicit error; it never makes a new key silently, so the machine identity cannot change without you knowing. The recovery is the identity-key change (`tenzro-node identity-key`) or re-enrolment.

The floor is macOS 14. macOS 27 runs on Apple silicon only; the Intel archive serves Intel Macs on macOS 14 to 26.

Trade-off to tell your users: an Enclave key is not bound to the signer. The key blob in `~/Library/Application Support/Tenzro/device-keys` only unwraps on that Mac's Secure Enclave, but any local program that can read the blob can ask the Enclave to use it. A key made with user presence (`userPresence`) adds a biometric or password prompt for each use.
