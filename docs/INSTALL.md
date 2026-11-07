# Install Tenzro

One native installer per operating system gets you from download to a working `tenzro` command, with
a plain-language hardware check, and ends by pointing you at the guided setup. Nothing starts by
itself: no service is installed or enabled, nothing joins the network, and no key is created until
you choose to in `tenzro setup`.

| You use | Install | You get |
|---|---|---|
| Debian, Ubuntu | `tenzro-cpu_<version>_amd64.deb` or `tenzro-cuda_<version>_arm64.deb` | `tenzro`, `tenzro-node`, `tenzro-check` on your PATH |
| Fedora, RHEL and relatives | `tenzro-cpu-<version>.x86_64.rpm` or `tenzro-cuda-<version>.aarch64.rpm` | the same |
| Windows 10 and 11 (x86-64) | `tenzro-<version>-windows-x86_64-cuda.msi` | the same, a Start Menu entry, an uninstaller |
| macOS 11 and newer | `tenzro-<version>-macos.pkg` (Apple silicon and Intel in one file) | the same, a launcher in Applications |

Every installer repackages the exact files of the signed release archive it names (the package
records that archive's SHA-256 and the release commit). Nothing is rebuilt. The package files are
listed in the release's signed `SHA256SUMS` next to the archives, so you verify them the same way.

## 1. Verify, then install

Verification is [docs/VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md). In short, in the folder holding the
download and the release's `SHA256SUMS`, `SHA256SUMS.sig` and `tenzro-release.pub`:

```bash
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing        # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

Do this first. The installers themselves are not yet signed with an operating-system code-signing
certificate (see "Unsigned installers" below), so the release signature is what proves the file is ours.

### Linux

```bash
# Debian, Ubuntu (24.04 or newer)
sudo apt install ./tenzro-cpu_0.2.0-1_amd64.deb

# Fedora (40 or newer), RHEL 10 and relatives
sudo dnf install ./tenzro-cpu-0.2.0-1.x86_64.rpm
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

Tenzro hardware check (version 0.2.0-1)
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

### Windows

Double-click `tenzro-<version>-windows-x86_64-cuda.msi`, or from an elevated prompt:

```bat
msiexec /i tenzro-0.2.0-windows-x86_64-cuda.msi
```

The wizard shows a licence page, an install folder (default `C:\Program Files\Tenzro`), a choice of how to
add Tenzro to your PATH (for all users, for you only, or not at all), and a final page with a ticked box
"Run Tenzro setup now". Leave it ticked and a terminal window opens, runs the hardware check, and starts
`tenzro setup`. The Start Menu gets "Tenzro" (a terminal running `tenzro`), "Tenzro setup" and "Tenzro hardware check".

Silent install for scripts and fleets (no final page, nothing launched):

```bat
msiexec /i tenzro-0.2.0-windows-x86_64-cuda.msi /qn ADDTOPATH=system INSTALLFOLDER="C:\Tools\Tenzro"
```

`ADDTOPATH` is `system`, `user` or `none`. The MSI is per-machine, so it asks for administrator rights; it installs no service, and the hardware check runs only when you tick the final box, choose "Tenzro hardware check" or type `tenzro-check`, never during the install itself. Uninstall from "Apps > Installed apps >
Tenzro", or `msiexec /x tenzro-0.2.0-windows-x86_64-cuda.msi`; the PATH entry is removed with it. This is the CUDA
build and needs an NVIDIA GPU with a current driver; on a machine without one the hardware check says so and
tells you to use the command line only or another build.

### macOS

Open `tenzro-<version>-macos.pkg` and follow the installer, or:

```bash
sudo installer -pkg tenzro-0.2.0-macos.pkg -target /
```

One file serves both kinds of Mac: Apple silicon gets the Metal build, Intel gets the CPU build. It installs
into `/usr/local/lib/tenzro` with links in `/usr/local/bin`, plus a launcher called **Tenzro** in Applications. The
launcher opens Terminal, shows the hardware check and starts `tenzro setup`. macOS's installer has no "run after install"
checkbox, so the last page tells you to open that launcher or run `tenzro setup`.

On a Mac with a Secure Enclave the node keeps its identity keys there and they cannot be exported. A virtual
machine without a Secure Enclave cannot run a validator node.

Remove: `sudo tenzro-uninstall`. It removes the programs, the launcher and the installer receipt; your keys and data are untouched.

## 2. First run

Whichever installer you used, the same three steps follow, in a terminal:

1. `tenzro-check` shows whether this machine can run the build you installed, in plain words, and what to do if not.
2. `tenzro setup` is the guided setup: your roles, your wallet, whether to provide compute or validate, and
   which models to use. Nothing is created before you confirm it. (`tenzro` alone opens the interactive menu.)
3. When you are ready, `tenzro setup` offers to install and start the node as a service (`--apply`). That is the first
   moment anything runs in the background, and it is your choice.

## 3. Manual, verified path (no installer)

Every release archive can still be used directly: verify it ([VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md)), unpack it, and
on Linux run `tenzro-node-install --sums SHA256SUMS --sig SHA256SUMS.sig --key tenzro-release.pub <archive>`, which
checks the archive against the signed manifest, refuses a build that does not match the machine, and installs under
`/usr/local`. On Windows and macOS, unpack the archive and put its `bin` directory on your PATH.

## 4. Unsigned installers

The installers are not signed with an operating-system code-signing certificate yet. What you will see, and why it is
safe to continue only after you verified the file as above:

* **Windows**: opening the MSI shows a User Account Control prompt that names the publisher as "Unknown publisher"
  instead of "Tenzro". A file downloaded with a browser also carries a web-origin mark, and Windows SmartScreen may
  show "Windows protected your PC": choose "More info", then "Run anyway". Neither prompt appears when you install
  with `msiexec` from a prompt on a file you copied locally.
* **macOS**: Gatekeeper refuses a package from an unidentified developer: "tenzro-0.2.0-macos.pkg cannot be opened
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
