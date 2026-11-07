# Install Tenzro and run it for the first time

Install it, run `tenzro`, and follow the screens. The first run checks your machine, asks whether you want to
use the network, provide compute, run a validator or try a local chain, sets up your keys, starts the node and
shows the console. You do not need to be an expert.

## Easy path

Native packages are pre-release and unsigned: your system may warn you the first time you open one. Windows shows
"Unknown publisher" and macOS asks you to confirm. [INSTALL.md](INSTALL.md) says what you will see and how to check the
download first.

### Windows

1. Download `tenzro-<version>-windows-x86_64-cuda.msi` from the release page and open it. Windows asks for administrator
   rights; the installer adds `tenzro` to your PATH.
2. Open a new terminal and run `tenzro`.

The Windows installer is the CUDA build and needs an NVIDIA GPU with a current driver to serve models; the
command line works without one.

### macOS

1. Download `tenzro-<version>-macos.pkg` and open it. One file serves Apple silicon and Intel.
2. Open a new terminal and run `tenzro`.

### Linux

1. Run the install script. It needs no `sudo`.

```bash
curl -fsSL https://downloads.tenzro.com/install.sh | sh
```

2. Run `tenzro`. If the installer says `~/.local/bin` is not on your PATH, it prints the one line to run first.

A fresh Ubuntu needs `curl` and `openssl` first (`sudo apt-get install -y curl openssl ca-certificates`).
The `.deb` and `.rpm` packages are described in [INSTALL.md](INSTALL.md).

### What `tenzro` does the first time

On a machine with no Tenzro settings, `tenzro` opens a full-screen first run: a welcome, a check of this machine, and
one question (use the network, provide compute, run a validator, or try a local chain). After setup, `tenzro` opens the
console (Overview, Wallet, Models, Validators, Governance, Health); press `q` to leave it. Outside a terminal (a script
or a pipe) `tenzro` prints the command list instead.

Verified so far: the Windows MSI, the Linux arm64 install script and the macOS package each installed, started the
first run and uninstalled cleanly (details in [What is verified](#what-is-verified-and-what-is-not)).

### Update and remove

Windows: "Apps > Installed apps > Tenzro", or `msiexec /x` on the MSI. macOS: `sudo tenzro-uninstall`. Linux script
install: `curl -fsSL https://downloads.tenzro.com/install.sh | sh -s -- --uninstall`. Your keys and data in `~/.tenzro`
are left alone.

## Advanced and manual setup

Everything below is for people who want the details: what the install script does, verifying a download by hand,
Windows PowerShell, containers, edge devices such as a Raspberry Pi, the screens of the earlier command-line setup, and
troubleshooting.

Windows (PowerShell script, instead of the MSI):

```powershell
irm https://downloads.tenzro.com/install.ps1 | iex
```

The Linux script needs no `sudo`; the download is 95 MB for the Linux x86_64 build and the rest is under two seconds.

### What the installer does

1. Detects the system (Linux or macOS; x86_64 or arm64), the glibc version and whether an NVIDIA GPU is present, and
   picks the archive from the release's `SHA256SUMS`: CUDA build with an NVIDIA GPU, CPU build without, Metal build on
   Apple silicon.
2. Downloads `SHA256SUMS` and `SHA256SUMS.sig` and verifies the signature with `openssl` against the release public
   key embedded in the script. It first checks that the embedded key has the published fingerprint
   (`c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d`). A bad signature stops the install.
3. Downloads the archive and checks its SHA-256 against the signed list. A mismatch (altered or truncated download)
   deletes the file and stops the install.
4. Unpacks to `~/.tenzro/install/versions/<archive>-<hash>/`, refusing paths that would escape that folder and files that
   are not executables for this system, then runs the binary's own hardware check (`tenzro-node hardware`) and, on
   Linux when `bash`, `file` and `readelf` are present, the archive's install gate in dry-run.
5. Links `tenzro` and `tenzro-node` into `~/.local/bin`. If that folder is not on your `PATH` it offers to add it to your
   shell profile (a marked block; nothing is edited without your yes, or `--modify-path`), and it never overwrites a
   `tenzro` it did not create.

Nothing is installed unless steps 2 and 3 pass. No part of the install needs administrator rights, and the
machine's identity keys are not touched: they are created later, in hardware, by `tenzro setup` or `tenzro-node`.

Options (`curl ... | sh -s -- <option>`): `--dry-run` (verify the signed list and say what would happen),
`--prefix DIR`, `--bin-dir DIR`, `--version V` (refuse unless the release is V), `--target NAME`, `--from DIR`
(offline: a folder with `SHA256SUMS`, `SHA256SUMS.sig` and the archive), `--modify-path`, `--no-modify-path`,
`--uninstall`. Environment: `TENZRO_HOME`, `TENZRO_BIN_DIR`, `NO_COLOR`.

The script itself is covered by TLS only: it is served from `downloads.tenzro.com`, and its SHA-256 is published beside
it (`install.sh.sha256`). To trust nothing but the release key, use the manual steps below.

##### Verify it yourself instead

```bash
curl -fsSLO https://downloads.tenzro.com/SHA256SUMS
curl -fsSLO https://downloads.tenzro.com/SHA256SUMS.sig
curl -fsSLO https://downloads.tenzro.com/tenzro-release.pub
openssl pkey -pubin -in tenzro-release.pub -outform DER | sha256sum          # must print c88aaee7...aeb72d
base64 -d SHA256SUMS.sig > sig.der
openssl dgst -sha256 -verify tenzro-release.pub -signature sig.der SHA256SUMS   # must print Verified OK
curl -fsSLO https://downloads.tenzro.com/tenzro-node-linux-x86_64-cpu.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf tenzro-node-linux-x86_64-cpu.tar.gz
./tenzro-node-linux-x86_64-cpu/bin/tenzro --version
```

`cosign verify-blob` works as well; see [VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md).

### First run, screen by screen

These screens were captured from the live release (0.2.0) in a clean Ubuntu 24.04 container run as a normal user, on a
machine with no TPM and no GPU, where the public network name `rpc.tenzro.com` did not resolve. Colour is dropped here;
on a terminal the accent is one periwinkle and `NO_COLOR` turns it off.

**1. Install.** One command, one result:

```
Installing Tenzro

  machine     linux x86_64, glibc 2.39, no GPU
  signature   verified, release key c88aaee7
  build       tenzro-node-linux-x86_64-cpu
  downloading tenzro-node-linux-x86_64-cpu.tar.gz
  checksum    verified, sha256 5d1d0a008f83
  self-check  build CPU, 0 GPU(s), startup ok
  gate        accepted for the cpu role
  install     /home/u/.tenzro/install/versions/tenzro-node-linux-x86_64-cpu-5d1d0a008f83
  linked      /home/u/.local/bin/tenzro, /home/u/.local/bin/tenzro-node
  path        /home/u/.local/bin is not on your PATH

Tenzro 0.2.0 is installed (66s)

Add it to this terminal, then start:

    export PATH="/home/u/.local/bin:$PATH" && tenzro
```

On an interactive terminal the installer instead asks `~/.local/bin is not on your PATH. Add it to ~/.bashrc? [Y/n]`, and
the last line is just `tenzro`.

**2. `tenzro`.** On a terminal it shows the logo, a line saying whether a node answers, and a menu:

```
  Not connected to a node (http://127.0.0.1:8545)

? What would you like to do?
> Wallet & Tokens
  AI Models & Inference
  Bridge & Cross-Chain
  Identity & Credentials
  Payments & Settlement
  Security (Crypto, TEE, ZK)
  Developer (Contracts, Tasks)
  Network & Governance
  Exit
```

That menu is for people who already have a node to talk to. A new user runs `tenzro setup` (screen 3) first.
Outside a terminal (a script, a pipe) `tenzro` prints the command list and exits 0.

**3. `tenzro setup`.** The guided path. It detects the hardware, then asks one question: use the public network, run
your own local network, or join a private network (`--path network|local|private`). Roles and the machine name
follow, with defaults. It stops early, with the fix, when the machine is not ready:

```
◇  Hardware
│    CPU                Intel(R) Xeon(R) CPU E5-1660 v4 @ 3.20GHz (8 cores / 8 threads)
│    Memory             63 GB
│    GPU                none detected
│    TEE                not available
◇  Preflight
▲  TPM 2.0: no /dev/tpmrm0 on this machine
│      Turn the TPM on in the firmware settings (it may be called fTPM, PTT or Security Device), then reboot.
│      No TPM at all (a Raspberry Pi, for example): the identity key can live in another machine's TPM; see docs/NODE.md.
Error: this machine is not ready: fix the items marked above, then run `tenzro setup` again
```

That is the `--path local` outcome on a machine with no TPM. `--path network` on the same machine falls back to a
passkey ("Autonomous operation unavailable - no TPM detected on this machine"), opens your browser to create the passkey,
and then needs the public network to finish; if the network is unreachable it ends with
`Error: Cannot connect to https://rpc.tenzro.com`.

**4. `tenzro dev`.** A local single-validator chain on your machine, no public network needed. Keys live in hardware, so it
needs a TPM 2.0 or a Mac with a Secure Enclave. Without one it says so in one line:

```
Error: tenzro dev keeps every key in this machine's hardware key store (a TPM 2.0 on Linux or Windows, the
Secure Enclave on macOS), and none was found. Keys are never held in software or in files, so run it on a machine
with a TPM or a Secure Enclave.
```

With one it prints the RPC address (`http://127.0.0.1:8545`), chain id (1337) and the funded client account, and runs until
Ctrl+C. Open a second terminal and use the other commands against it (`tenzro status`, `tenzro model list`, ...). The CLI
talks to `http://127.0.0.1:8545` by default.

**5. `tenzro status`** says what is running and the next thing to do:

```
Node Status:
! The node is not answering.
  Next   The node is not answering. Start it with `tenzro setup --apply`, or check the service: `sudo systemctl status tenzro-node`.
```

### Choose your path

| You want to | Run | Needs |
|---|---|---|
| Use the network (wallet, models, payments) | `tenzro setup --path network` | the public network; a browser for the passkey |
| Provide compute (models, storage) | `tenzro setup --mode provide`, then `tenzro join --provider` | a node on this machine, TNZO for the bond (`tenzro sponsor check`) |
| Validate | `tenzro setup --mode validate`, then `tenzro setup --apply` | a TPM 2.0 or Secure Enclave, 10,000 TNZO of stake (or a sponsorship) |
| Try it on this machine, no network | `tenzro dev` | a TPM 2.0 or a Mac |
| Build a private network | `tenzro setup --path local --network-name lab` | a TPM 2.0 or a Mac |

To point the CLI at a particular node, most commands take `--rpc <url>` (`join`, `setup`); `tenzro model list` takes
`--catalog-rpc <url>`. The default is `http://127.0.0.1:8545`, and `https://rpc.tenzro.com` for `join`.

### Hardware: what you see and what to do

| Situation | What you see | What to do |
|---|---|---|
| No TPM (VM, container, many laptops) | installer: "This machine has no TPM 2.0..."; `tenzro-node`/`tenzro dev`/`setup --path local`: "this machine has no TPM 2.0 ... or Secure Enclave" | Use the CLI and join with a passkey (`tenzro setup --path network`); to run a node use a machine with a TPM 2.0, enable fTPM/PTT in firmware, or on a Raspberry Pi hold the key in another machine's TPM (docs/NODE.md) |
| TPM present but not provisioned | `tenzro-node`: "run `tenzro-node tpm provision` as the node user" | `tenzro setup` offers to run it; or run it once yourself |
| No GPU | installer picks the CPU build; self-check "0 GPU(s)" | nothing; GPU roles need a GPU |
| NVIDIA GPU, CPU build | installer note: "an NVIDIA GPU is present, but this release's x86_64 Linux build is CPU-only; the GPU is not used" | none today: the published Linux x86_64 build is CPU-only |
| glibc older than 2.39 (Debian 12, Ubuntu 22.04) | "this system's glibc is too old ... needs glibc 2.39 or newer and this machine has 2.36" | Ubuntu 24.04, Debian 13, Fedora 40 or newer, or a container based on one |
| Alpine (musl) | "this Linux uses musl libc" | use a glibc image |
| Linux arm64 without an NVIDIA GPU (Raspberry Pi) | installer picks `tenzro-node-linux-aarch64-cpu.tar.gz` on Trixie-class glibc, `tenzro-node-linux-aarch64-cpu-bookworm.tar.gz` on Bookworm-class glibc | both archives install-gate pass; the Bookworm archive also starts correctly under qemu-user emulation of a Cortex-A72 and a Cortex-A76 — see [docs/LINUX-AARCH64-SUPPORT.md](LINUX-AARCH64-SUPPORT.md) |
| Jetson (NVIDIA GPU, arm64) | installer picks `tenzro-node-linux-aarch64-cuda-orin.tar.gz` on a Jetson Orin device tree, `tenzro-node-linux-aarch64-cuda.tar.gz` on Jetson Thor | both archives install-gate pass on JetPack 7.x; Jetson Orin on JetPack 6.x (Ubuntu 22.04, glibc 2.35, CUDA 12.6) has no archive in 0.2.1 — see [docs/LINUX-AARCH64-SUPPORT.md](LINUX-AARCH64-SUPPORT.md) |
| Windows without an NVIDIA GPU | installer note that the Windows build is the CUDA build | the CLI is installed; GPU features will not work |

### When the public network is unreachable

At the time of the 0.2.0 release `rpc.tenzro.com` did not resolve from the test machine. Commands that need it fail
with a connection error that names the address, for example:

```
Error: Cannot connect to https://rpc.tenzro.com: error sending request for url (https://rpc.tenzro.com/)
```

and `tenzro model list` / `tenzro node status` against the default local node say `Connection refused (os error 111)`:
nothing is listening on `127.0.0.1:8545`. What still works without any network:

- `tenzro version`, `--help`, every command's `--help`; `tenzro-node hardware`; `tenzro crypto verify`.
- On a machine with a TPM 2.0 or a Secure Enclave: `tenzro dev` (a local chain), `tenzro setup --path local`.

On a machine with neither a TPM nor a network, there is nothing to run yet besides reading the help; that is a limit of the
0.2.0 binaries, not of the install.

### The doctor checklist

Run `tenzro doctor` (see [CLI.md](CLI.md)). It reports the machine's hardware key store (TPM or Secure
Enclave), whether setup is needed, whether a node is running, free disk space, and names the one thing
to do next if anything blocks Tenzro. For a manual walk-through, run these in order and stop at the
first that fails; each line says what to do.

```bash
tenzro version && tenzro-node --version          # tenzro 0.2.1, tenzro-node 0.2.0; if "command not found": export PATH="$HOME/.local/bin:$PATH"
command -v tenzro                                # should be ~/.local/bin/tenzro (another path = an older copy shadows it)
tenzro-node hardware                             # build: CPU|CUDA, gpus, startup: ok
getconf GNU_LIBC_VERSION                         # Linux: 2.39 or newer
ls -l /dev/tpmrm0 && id -nG | tr ' ' '\n' | grep -x tss   # Linux: TPM device present, you are in the tss group
command -v tpm2_getcap                           # Linux, autonomous operator: tpm2-tools installed
curl -sS -m 5 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
  https://rpc.tenzro.com                         # public network: a JSON result; "Could not resolve host" = network down or no DNS
curl -sS -m 5 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
  http://127.0.0.1:8545                          # your local node (tenzro dev / setup --apply)
tenzro status                                    # what is running and the next step
tenzro-node doctor                               # can peers reach this node (run on the node's machine)
df -h ~                                          # about 300 MB for one install
```

### Update, uninstall

Update: run the installer again. It fetches the signed list, and if the archive it lists is already installed it
downloads nothing; otherwise it installs the new version beside the old one, switches the `current` link and keeps the
previous version. There is no `tenzro update` command.

Remove: `curl -fsSL https://downloads.tenzro.com/install.sh | sh -s -- --uninstall` removes the links, `~/.tenzro/install`
and the profile block if it added one. It leaves `~/.tenzro` itself (settings, node data) alone.

### What is verified, and what is not

See [docs/HARDWARE-COVERAGE.md](HARDWARE-COVERAGE.md) for the platforms each release archive is built
and install-tested for.

Verified by running the scripts: Ubuntu 24.04 and Fedora 42 (x86_64, rootless containers, installer run as a normal user):
install, update, uninstall, `--dry-run`, `--from` (offline), `--modify-path`; refusals for a tampered archive, a truncated
archive, a tampered signature and an altered hash list; Debian 12 (refused for glibc, with the fix); Alpine (refused
for musl); a macOS archive on Linux (refused, wrong system); missing `openssl` (refused); the shell scripts
parse under `dash` and `busybox sh`. `install.ps1` parses and its signature check verifies the real release and
rejects a tampered signature and list under PowerShell 7 on Linux.

Verified on the 0.2.1 packages (first run on a real terminal, install, uninstall): the Windows 11 MSI, Linux
arm64 through the install script (Ubuntu 24.04 container, GPU hidden) and the macOS package (arm64). Not verified: Linux
x86_64 with the 0.2.1 archive, the `.deb` and `.rpm` packages, Windows Terminal as an app, macOS on Intel, and the
NVIDIA GPU path (`nvidia-smi` detection and the CUDA archive).
