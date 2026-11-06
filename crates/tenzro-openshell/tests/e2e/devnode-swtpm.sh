#!/usr/bin/env bash
# A Tenzro developer chain for the OpenShell end-to-end test, on its own software TPM.
#
#   devnode.sh start                     start a single-validator tenzro-node chain from a genesis file this script
#                                        writes: the node's validator entry, two machine roots (root-a, root-b) and
#                                        the node account funded, and the swtpm local CA as the TPM endorsement root;
#                                        prints "url <rpc url>", "log <path>" and "root <ns> <account>"
#   devnode.sh admit                     once the node answers: register its machine identity on chain with its TPM
#                                        attestation (validator register-machine), which admits that TPM under the
#                                        machine root, so the keys it certifies for the agents it serves are accepted
#   devnode.sh delegate <ns> <name>      the root <ns> bonds and delegates agent <name> under the Terms read from
#                                        stdin, served by this node; prints "agent <did>" and "controller <did>"
#   devnode.sh revoke-root <ns> <reason> the root <ns> revokes itself on chain, and with it every agent it delegated
#   devnode.sh stop                      stop the node (exact unit); the swtpm stays up for the next run
#
# The roots are machine roots: accounts keyed in the same swtpm under their own key namespaces, signing every
# approval and transaction there through the tenzro CLI (bin/tenzro).
#
# PRIVATE TEST CHAIN ONLY. The node sees the swtpm as /dev/tpmrm0 in its own private /dev; nothing appears at the
# host /dev/tpm0 or /dev/tpmrm0. Its identity is provisioned in that swtpm under the namespace openshell-e2e.
# The genesis file is this run's own (run/genesis.toml): the swtpm local CA is an endorsement root on this chain only.
#
# SWTPM_PREFIX names the swtpm/libtpms install the TPM runs from (its bin, etc and local CA): a user-space build with
# no known vulnerability, never the distribution's packages.
set -euo pipefail
#
# DEVNODE_HOME holds bin/tenzro-node and the run's state and DEVNODE_SRC is this repository (for the swtpm helpers).
# The node listens on loopback only; a test on another host reaches its RPC through an SSH port forward.
D=${DEVNODE_HOME:?set DEVNODE_HOME}
NODE=$D/bin/tenzro-node
CLI=$D/bin/tenzro
ROOTS=(root-a root-b)
SRC=${DEVNODE_SRC:?set DEVNODE_SRC to this repository}
SWTPM_PREFIX=${SWTPM_PREFIX:?set SWTPM_PREFIX to the user-space swtpm/libtpms install}
[[ -x $SWTPM_PREFIX/bin/swtpm && -x $SWTPM_PREFIX/bin/swtpm_setup ]] || { echo "FAIL: no swtpm in $SWTPM_PREFIX" >&2; exit 1; }
ST=/var/lib/swtpm/openshell-e2e
TPM_UNIT=tzc-openshell-e2e-swtpm
NODE_UNIT=tzc-openshell-e2e-node
ME=$(id -un)
log() { echo "$(date -u +%FT%TZ) $*" >> "$D/devnode.log"; }
die() { echo "FAIL: $*" >&2; exit 1; }
# shellcheck source=/dev/null
source "$SRC/scripts/cluster/swtpm-host.sh"

tpm_up() {
  if systemctl is-active --quiet "$TPM_UNIT" && [[ -s $D/device && -c $(cat "$D/device") ]] \
    && [[ $(cat "$D/swtpm-prefix" 2>/dev/null) == "$SWTPM_PREFIX" ]]; then return; fi
  # A TPM this script started from another install is replaced, state and all.
  if systemctl is-active --quiet "$TPM_UNIT"; then sudo -n systemctl stop "$TPM_UNIT"; fi
  sudo -n systemctl reset-failed "$TPM_UNIT" 2>/dev/null || true
  rm -f -- "$D/device" "$D/swtpm-prefix"
  # The key blobs of the previous TPM do not load into a new one.
  rm -rf -- "${D:?}/device-keys"
  [[ -e /sys/class/tpm/tpm0 ]] || die "TPM index 0 is free; start a run that holds it first"
  sudo -n mkdir -p "$ST"
  sudo -n env "PATH=$SWTPM_PREFIX/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$SWTPM_PREFIX/bin/swtpm_setup" \
    --tpm "$SWTPM_PREFIX/bin/swtpm socket" --config "$SWTPM_PREFIX/etc/swtpm_setup.conf" \
    --tpm2 --tpmstate "$ST" --create-ek-cert --create-platform-cert --overwrite > "$D/setup.out" 2>&1 \
    || die "swtpm_setup: $(tail -3 "$D/setup.out")"
  sudo -n systemd-run --unit="$TPM_UNIT" -p MemoryMax=128M -p CPUQuota=25% \
    "$SWTPM_PREFIX/bin/swtpm" chardev --tpm2 --vtpm-proxy --tpmstate dir="$ST" --flags startup-clear >/dev/null
  # swtpm announces its device in its unit log once the kernel made it.
  local i t=""; for ((i = 0; i < 120; i++)); do
    t=$(swtpm_index "$TPM_UNIT" || true); [[ -n $t && -c /dev/tpmrm$t ]] && break; sleep 1; done
  [[ -n $t && -c /dev/tpmrm$t ]] || die "swtpm created no resource-manager device"
  sudo -n udevadm settle
  sudo -n chown "$ME" "/dev/tpmrm$t"
  echo "/dev/tpmrm$t" > "$D/device"
  echo "$SWTPM_PREFIX" > "$D/swtpm-prefix"
  tpm2_readpublic -T "device:/dev/tpmrm$t" -c 0x81010020 >/dev/null 2>&1 \
    || tpm2_createek -T "device:/dev/tpmrm$t" -c 0x81010020 -G ecc -u "$D/ek.pub" >/dev/null
  # The local CA's intermediate goes in the first TCG EK certificate chain index, where a manufacturer stores its
  # intermediates, so the EK certificate chains to the local CA root this chain's genesis names.
  sudo -n cat "$SWTPM_PREFIX/var/lib/swtpm-localca/issuercert.pem" | openssl x509 -outform DER > "$D/ek-chain.der"
  tpm2_nvdefine -T "device:/dev/tpmrm$t" -C o -s "$(stat -c %s "$D/ek-chain.der")" \
    -a "ownerread|ownerwrite|authread|authwrite|no_da" 0x01c00100 >/dev/null
  tpm2_nvwrite -T "device:/dev/tpmrm$t" -C o -i "$D/ek-chain.der" 0x01c00100
  log "swtpm $TPM_UNIT at /dev/tpmrm$t ($("$SWTPM_PREFIX/bin/swtpm" --version | head -1))"
}

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

# One CLI command bound to the swtpm, as this user.
cli() {
  tpm_unit_opts "$(cat "$D/device")"
  sudo -n systemd-run --wait --pipe --quiet --collect --unit="$NODE_UNIT-cli-$$-$RANDOM" -p User="$ME" -p MemoryMax=2G \
    -p "Environment=TENZRO_DEVICE_KEY_DIR=$D/device-keys" -p "WorkingDirectory=$D/run" "${TPM_OPTS[@]}" "$CLI" "$@" \
    | sed 's/\x1b\[[0-9;]*m//g'
}

rpc_url() { echo "http://127.0.0.1:$(cat "$D/run/rpc")"; }

# The JSON object a CLI command printed after its header lines.
json_of() { python3 -c 'import json,sys; t=sys.stdin.read(); print(json.dumps(json.loads(t[t.index("{"):])))'; }

start() {
  systemctl is-active --quiet "$NODE_UNIT" && sudo -n systemctl stop "$NODE_UNIT"
  sudo -n systemctl reset-failed "$NODE_UNIT" 2>/dev/null || true
  tpm_up
  tpm_unit_opts "$(cat "$D/device")"
  local run=$D/run
  rm -rf -- "${run:?}"; mkdir -p "$run/data" "$D/device-keys"; chmod 700 "$D/device-keys"
  local rpc web mcp a2a p2p; rpc=$(free_port); web=$(free_port); mcp=$(free_port); a2a=$(free_port); p2p=$(free_port)
  cat > "$run/node.toml" <<TOML
data_dir = "$run/data"
serve_agents = true
model_id = "e2e-no-model"
forecaster_id = "e2e-no-forecaster"
rpc_addr = "127.0.0.1:$rpc"
web_addr = "127.0.0.1:$web"
mcp_addr = "127.0.0.1:$mcp"
a2a_addr = "127.0.0.1:$a2a"
metrics_enabled = false
hardware_key_namespace = "openshell-e2e"

[iroh]
bind_addr = "127.0.0.1:$p2p"

[storage]
memory_mb = 256
TOML
  sudo -n systemd-run --wait --pipe --quiet --collect --unit="$NODE_UNIT-provision" -p User="$ME" -p MemoryMax=2G \
    -p "Environment=TENZRO_DEVICE_KEY_DIR=$D/device-keys" "${TPM_OPTS[@]}" "$NODE" -c "$run/node.toml" tpm provision \
    > "$run/provision.out" 2>&1 || die "tpm provision: $(tail -3 "$run/provision.out")"
  echo "$rpc" > "$run/rpc"
  local fund=() ns acct
  # The node's own account (its identity key's), which registers its machine identity, and the roots.
  local node_acct; node_acct=$(sed 's/\x1b\[[0-9;]*m//g' "$run/provision.out" | sed -n 's/^node account *//p' | tr -d ' ')
  [[ $node_acct =~ ^0x[0-9a-fA-F]{64}$ ]] || die "provision printed no node account"
  fund+=("$node_acct")
  for ns in "${ROOTS[@]}"; do
    acct=$(cli wallet create-local --key-namespace "$ns" | sed -n 's/^ *Account[: ]*//p' | tr -d ' ' | head -1)
    [[ $acct =~ ^0x[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$ ]] || die "root $ns has no account: '$acct'"
    (( ${#acct} == 42 )) && acct=${acct}000000000000000000000000
    echo "$acct" > "$run/account-$ns"
    fund+=("$acct")
  done
  # This chain's genesis: the node's own validator entry, the funded accounts, a developer chain's time rules, and
  # the swtpm local CA as the TPM endorsement root the machine admissions chain to.
  sudo -n systemd-run --wait --pipe --quiet --collect --unit="$NODE_UNIT-entry" -p User="$ME" -p MemoryMax=2G \
    -p "Environment=TENZRO_DEVICE_KEY_DIR=$D/device-keys" "${TPM_OPTS[@]}" "$NODE" -c "$run/node.toml" \
    validator-entry --stake 1000000 > "$run/entry.raw" 2>&1 || die "validator-entry: $(tail -3 "$run/entry.raw")"
  sudo -n cat "$SWTPM_PREFIX/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem" > "$run/swtpm-root.pem"
  python3 - "$run/entry.raw" "$run/swtpm-root.pem" "${fund[@]}" > "$run/genesis.toml" <<'PY' || die "genesis"
import sys
raw = open(sys.argv[1]).read()
entry = raw[raw.index("[[validators]]"):].strip()
pem = open(sys.argv[2]).read().strip()
assert pem.startswith("-----BEGIN CERTIFICATE-----"), "no swtpm local CA root"
accounts = []
for a in sys.argv[3:]:
    a = a.lower().removeprefix("0x")
    if a not in accounts:
        accounts.append(a)
print("version = 1\nchain_id = 1337\ntimestamp = 0\n")
print("[time]\ncheckpoint_interval_ms = 250\nepoch_checkpoints = 240\nhandover_confirmations = 2\n"
      "announcement_lifetime_ms = 21600000\ncompact_interval_ms = 15000\ncompact_handoff_ms = 15000\n"
      "leader_slots = 2\ncalendar_scale = 1\nidle_round_interval_ms = 250\n")
print("[economy]\ntpm_endorsement_roots_pem = ['''\n" + pem + "\n''']\nbridge_mint_per_mint_tnzo = 10000\n"
      "bridge_mint_per_epoch_tnzo = 100000\nbridge_attested_per_mint_tnzo = 2000\nbridge_attested_per_epoch_tnzo = 20000\n"
      "\n[[economy.bridge_outflow]]\nunit = \"TNZO\"\nper_epoch = \"100000000000000000000000\"\n")
for a in accounts:
    print(f'[[accounts]]\naddress = "{a}"\nbalance = 1000000\n')
print(entry)
PY
  sudo -n systemd-run --unit="$NODE_UNIT" --collect -p User="$ME" -p MemoryMax=6G -p MemorySwapMax=0 -p CPUQuota=400% -p Nice=19 \
    -p "Environment=TENZRO_DEVICE_KEY_DIR=$D/device-keys" -p "Environment=RUST_LOG=warn,tenzro_node=info" \
    -p "StandardOutput=append:$run/node.log" -p "StandardError=append:$run/node.log" "${TPM_OPTS[@]}" \
    "$NODE" -c "$run/node.toml" --genesis "$run/genesis.toml" --roles validator --boot-nodes "" >/dev/null
  log "node $NODE_UNIT rpc http://127.0.0.1:$rpc genesis $(sha256sum "$run/genesis.toml" | cut -c1-16)"
  echo "url http://127.0.0.1:$rpc"
  echo "log $(hostname):$run/node.log"
  for ns in "${ROOTS[@]}"; do echo "root $ns $(cat "$run/account-$ns")"; done
}

admit() {
  local out; out=$(cli validator register-machine --key-namespace openshell-e2e --rpc "$(rpc_url)" 2>&1) \
    || grep -q "already registered" <<<"$out" || die "register-machine: $out"
  echo "$out" > "$D/run/admit.out"
  echo "admitted"
}

delegate() {
  local ns=$1 name=$2 run=$D/run
  cat > "$run/terms-$name-$ns.json"
  local out; out=$(cli agent delegation create-as-machine --terms "$run/terms-$name-$ns.json" --key-namespace "$ns" \
    --bond 1000000000000000000 --rpc "$(rpc_url)") || die "create-as-machine: $out"
  echo "$out" > "$run/delegate-$name-$ns.out"
  OUT=$out python3 - "$run/root-$ns.did" <<'PY'
import json, os, sys
t = os.environ["OUT"]
v = json.loads(t[t.index("{"):])
did = (v.get("identity") or {}).get("did") or v.get("did")
controller = (v.get("identity") or {}).get("controller_did") or v.get("controller_did")
if not did or not controller:
    sys.exit("create-as-machine printed no agent: " + t[:400])
open(sys.argv[1], "w").write(controller)
print("agent", did)
print("controller", controller)
PY
}

revoke_root() {
  local ns=$1 reason=$2 run=$D/run
  local did; did=$(cat "$run/root-$ns.did")
  local acct; acct=$(cat "$run/account-$ns")
  cli agent delegation challenge --account "$acct" --agent-did "$did" --reason "$reason" --format json --rpc "$(rpc_url)" revoke \
    | json_of > "$run/revoke-$ns.challenge.json"
  cli agent delegation sign --challenge "$run/revoke-$ns.challenge.json" --key-namespace "$ns" | json_of > "$run/revoke-$ns.sig.json"
  local p256; p256=$(cli wallet create-local --key-namespace "$ns" | sed -n 's/^ *P-256 public key[: ]*//p' | tr -d ' ' | head -1)
  python3 - "$run/revoke-$ns.challenge.json" "$run/revoke-$ns.sig.json" "$p256" > "$run/revoke-$ns.approval.json" <<'PY'
import json, sys
ch = json.load(open(sys.argv[1]))
sig = json.load(open(sys.argv[2]))
b = lambda h: list(bytes.fromhex(h.removeprefix("0x")))
print(json.dumps({"account": b(ch["account_address"]), "nonce": b(ch["nonce_hex"]),
                  "root_public_key": b(sys.argv[3]), "signature": sig["signature"]}))
PY
  cli identity revoke "$did" --approval "$run/revoke-$ns.approval.json" --reason "$reason" --key-namespace "$ns" \
    --format json --rpc "$(rpc_url)" > "$run/revoke-$ns.out" || die "identity revoke: $(tail -5 "$run/revoke-$ns.out")"
  echo "revoked $did"
}

stop() {
  if systemctl is-active --quiet "$NODE_UNIT"; then sudo -n systemctl stop "$NODE_UNIT"; fi
  sudo -n systemctl reset-failed "$NODE_UNIT" 2>/dev/null || true
}

case ${1:-} in
  start) shift; start "$@" ;;
  admit) admit ;;
  delegate) shift; delegate "$@" ;;
  revoke-root) shift; revoke_root "$@" ;;
  stop) stop ;;
  *) die "usage: devnode.sh start | admit | delegate <ns> <name> | revoke-root <ns> <reason> | stop" ;;
esac
