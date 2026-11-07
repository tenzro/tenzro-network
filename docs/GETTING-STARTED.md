# Install Tenzro and run it for the first time

One command installs the `tenzro` command line and the node. Then you run `tenzro`.

```bash
curl -fsSL https://downloads.tenzro.com/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://downloads.tenzro.com/install.ps1 | iex
```

It takes about a minute on an ordinary connection (the download is 95 MB for the Linux x86_64 build; the rest is
under two seconds). It needs no `sudo`. A fresh Ubuntu needs `curl` and `openssl` first
(`sudo apt-get install -y curl openssl ca-certificates`); Fedora and macOS already have them.

## What the installer does

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

### Verify it yourself instead

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

## First run, screen by screen

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

That menu is for people who already have a node to talk to. A new user should run `tenzro setup` (screen 3) first.
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

## Choose your path

| You want to | Run | Needs |
|---|---|---|
| Use the network (wallet, models, payments) | `tenzro setup --path network` | the public network; a browser for the passkey |
| Provide compute (models, storage) | `tenzro setup --mode provide`, then `tenzro join --provider` | a node on this machine, TNZO for the bond (`tenzro sponsor check`) |
| Validate | `tenzro setup --mode validate`, then `tenzro setup --apply` | a TPM 2.0 or Secure Enclave, 10,000 TNZO of stake (or a sponsorship) |
| Try it on this machine, no network | `tenzro dev` | a TPM 2.0 or a Mac |
| Build a private network | `tenzro setup --path local --network-name lab` | a TPM 2.0 or a Mac |

To point the CLI at a particular node, most commands take `--rpc <url>` (`join`, `setup`); `tenzro model list` takes
`--catalog-rpc <url>`. The default is `http://127.0.0.1:8545`, and `https://rpc.tenzro.com` for `join`.

## Hardware: what you see and what to do

| Situation | What you see | What to do |
|---|---|---|
| No TPM (VM, container, many laptops) | installer: "This machine has no TPM 2.0..."; `tenzro-node`/`tenzro dev`/`setup --path local`: "this machine has no TPM 2.0 ... or Secure Enclave" | Use the CLI and join with a passkey (`tenzro setup --path network`); to run a node use a machine with a TPM 2.0, enable fTPM/PTT in firmware, or on a Raspberry Pi hold the key in another machine's TPM (docs/NODE.md) |
| TPM present but not provisioned | `tenzro-node`: "run `tenzro-node tpm provision` as the node user" | `tenzro setup` offers to run it; or run it once yourself |
| No GPU | installer picks the CPU build; self-check "0 GPU(s)" | nothing; GPU roles need a GPU |
| NVIDIA GPU, CPU build | installer note: "an NVIDIA GPU is present, but this release's x86_64 Linux build is CPU-only; the GPU is not used" | none today: the published Linux x86_64 build is CPU-only |
| glibc older than 2.39 (Debian 12, Ubuntu 22.04) | "this system's glibc is too old ... needs glibc 2.39 or newer and this machine has 2.36" | Ubuntu 24.04, Debian 13, Fedora 40 or newer, or a container based on one |
| Alpine (musl) | "this Linux uses musl libc" | use a glibc image |
| Linux arm64 without an NVIDIA GPU (Raspberry Pi) | "this release has no build that fits this machine" | the published arm64 build is the CUDA build; none for a plain CPU yet |
| Windows without an NVIDIA GPU | installer note that the Windows build is the CUDA build | the CLI is installed; GPU features will not work |

## When the public network is unreachable

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

## The doctor checklist

There is no `tenzro doctor` yet. Run these in order and stop at the first that fails; each line says what to do.

```bash
tenzro version && tenzro-node --version          # both 0.2.0; if "command not found": export PATH="$HOME/.local/bin:$PATH"
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

## Update, uninstall

Update: run the installer again. It fetches the signed list, and if the archive it lists is already installed it
downloads nothing; otherwise it installs the new version beside the old one, switches the `current` link and keeps the
previous version. `tenzro update` does not exist yet.

Remove: `curl -fsSL https://downloads.tenzro.com/install.sh | sh -s -- --uninstall` removes the links, `~/.tenzro/install`
and the profile block if it added one. It leaves `~/.tenzro` itself (settings, node data) alone.

## What is verified, and what is not

Verified by running the scripts: Ubuntu 24.04 and Fedora 42 (x86_64, rootless containers, installer run as a normal user):
install, update, uninstall, `--dry-run`, `--from` (offline), `--modify-path`; refusals for a tampered archive, a truncated
archive, a tampered signature and an altered hash list; Debian 12 (refused for glibc, with the fix); Alpine (refused
for musl); a macOS archive on Linux (refused, wrong system); missing `openssl` (refused); the shell scripts
parse under `dash` and `busybox sh`. `install.ps1` parses and its signature check verifies the real release and
rejects a tampered signature and list under PowerShell 7 on Linux.

Not verified: macOS (both architectures), Windows (the PowerShell script has not been run on Windows; the zip
layout, junction, PATH and self-check steps are reviewed only), Linux arm64, and the NVIDIA GPU path
(`nvidia-smi` detection and the CUDA archive).
