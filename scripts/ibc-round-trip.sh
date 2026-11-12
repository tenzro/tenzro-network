#!/usr/bin/env bash
# IBC between a Tenzro network and a local Cosmos chain running ibc-go v10
# with the 08-wasm module, over both IBC classic and IBC v2.
#
# Stages (run in order; each needs the ones before it):
#
#   chain       Start a single-validator Cosmos chain.
#   anchor      Print the chain's latest height and header hash: the anchor
#               a Tenzro route's light client trusts. The private test
#               network writes it into its genesis routes before it starts.
#   cosmos      Store Tenzro's light client (contracts/cosmos) through a
#               governance proposal, create two Tenzro clients, open the
#               classic handshakes on the Cosmos side (ConnOpenInit,
#               ChanOpenInit), register the v2 counterparty and send one v2
#               packet towards Tenzro.
#   record      Record the Cosmos chain's headers, validators and IBC store
#               proofs into a JSON fixture (the Tenzro-side tests replay it).
#   routes      Install both IBC routes on a running Tenzro network by
#               governance, on the standard track: propose, vote, wait out
#               the voting period and timelock, enact. Not needed when the
#               network's genesis installs them.
#   round-trip  With both routes installed: run the handshakes to OPEN, send
#               TNZO to the Cosmos chain, receive it there, acknowledge it on
#               Tenzro, and time out a second packet, for classic and for v2.
#               Every update of the Cosmos chain's client of Tenzro carries a
#               Groth16 finality proof: a STARK on an NVIDIA GPU host, wrapped
#               to Groth16 on an x86-64 host (docs/BRIDGE.md).
#   stop        Stop the Cosmos chain.
#
# Environment:
#   SIMD          simd built from ibc-go v10 modules/light-clients/08-wasm/testing/simapp/simd
#   WORK          working directory for chain data and artifacts (default: ./target/ibc-local)
#   WASM          the built light client (default: contracts/cosmos target, wasm32-unknown-unknown release)
#   WASM_OPT      binaryen's wasm-opt (version 116 or later), which lowers it to WebAssembly 1.0
#   COSMOS_CHAIN_ID  (default: ibc-local-1)
#   RPC_PORT, P2P_PORT, GRPC_PORT  local ports of the Cosmos node (defaults 36657, 36656, 39090)
#   ROUTE_CLASSIC, ROUTE_V2  Tenzro route names (defaults: ibc-local-classic, ibc-local-v2)
#   TENZRO_CHAIN_ID, TENZRO_GENESIS_HASH, TENZRO_COMMITTEE_ROOT, FINALITY_IMAGE_ID
#                 the Tenzro network the Cosmos client follows (round-trip; defaults are test values for cosmos/record)
#   FIXTURE       where `record` writes (default: crates/tenzro-bridge/tests/fixtures/cosmos_local_ibc.json)
#   routes and round-trip:
#   TENZRO        the tenzro CLI;  TENZRO_RPC  the node's RPC endpoint
#   PROVER_STARK  runs `tenzro-finality-prover stark` on the GPU host (built with --features cuda)
#   PROVER_WRAP   runs `tenzro-finality-prover wrap` on an x86-64 host with the Groth16 prover container
#   VOTERS        space-separated hardware key namespaces of validator nodes
#                 (their `hardware_key_namespace`): the first node's account
#                 proposes the routes, each validator's machine root votes
#   EXECUTOR_KEY_NAMESPACE  a funded client account that enacts passed proposals
#   KEY_NAMESPACE the relayer's hardware key namespace (signs its Tenzro transactions)
#   SENDER_KEY_NAMESPACE  the hardware key namespace of the account that sends TNZO out
#   ROUTE_VERIFIERS  the routes' attesting committee, as a VerifierQuorum JSON
#                 (inbound transfers need it; the round trip itself is proven)

set -euo pipefail

STAGE=${1:-}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIMD=${SIMD:?set SIMD to the 08-wasm simd binary}
WORK=${WORK:-$ROOT/target/ibc-local}
HOME_DIR=$WORK/cosmos
COSMOS_CHAIN_ID=${COSMOS_CHAIN_ID:-ibc-local-1}
RPC_PORT=${RPC_PORT:-36657}
P2P_PORT=${P2P_PORT:-36656}
GRPC_PORT=${GRPC_PORT:-39090}
NODE=tcp://127.0.0.1:$RPC_PORT
RPC_URL=http://127.0.0.1:$RPC_PORT
WASM=${WASM:-$ROOT/contracts/cosmos/target/wasm32-unknown-unknown/release/tenzro_wasm_client.wasm}
WASM_OPT=${WASM_OPT:-wasm-opt}
ROUTE_CLASSIC=${ROUTE_CLASSIC:-ibc-local-classic}
ROUTE_V2=${ROUTE_V2:-ibc-local-v2}
# The number in Tenzro's IBC identifiers on a route: the first eight bytes of
# the SHA-256 of the route's chain name, big-endian, in decimal.
idnum() { python3 -c "import hashlib,sys;print(int.from_bytes(hashlib.sha256(sys.argv[1].encode()).digest()[:8],'big'))" "$1"; }
FIXTURE=${FIXTURE:-$ROOT/crates/tenzro-bridge/tests/fixtures/cosmos_local_ibc.json}
TENZRO_CHAIN_ID=${TENZRO_CHAIN_ID:-1337}
TENZRO_GENESIS_HASH=${TENZRO_GENESIS_HASH:-0x$(printf '11%.0s' $(seq 32))}
TENZRO_COMMITTEE_ROOT=${TENZRO_COMMITTEE_ROOT:-0x$(printf '22%.0s' $(seq 32))}
FINALITY_IMAGE_ID=${FINALITY_IMAGE_ID:-0x84684b576dcba8ca62548bb2ef545eee3817bc5db36ac5a821847b5bd2b493a3}
KR=(--keyring-backend test --home "$HOME_DIR")
TXF=(--chain-id "$COSMOS_CHAIN_ID" --node "$NODE" "${KR[@]}" --gas 3000000 --fees 30000stake -y --output json)

log() { echo "== $*" >&2; }

addr() { "$SIMD" keys show relayer -a "${KR[@]}"; }

height() { curl -s "$RPC_URL/status" | jq -r .result.sync_info.latest_block_height; }

wait_height() {
    local target=$1
    until [ "$(height 2>/dev/null || echo 0)" -ge "$target" ] 2>/dev/null; do sleep 1; done
}

# Wait for a transaction and fail on a non-zero code.
wait_tx() {
    local hash=$1 out
    for _ in $(seq 60); do
        if out=$("$SIMD" q tx "$hash" --node "$NODE" --output json 2>/dev/null); then
            if [ "$(echo "$out" | jq -r .code)" != 0 ]; then
                echo "$out" | jq -r .raw_log >&2
                exit 1
            fi
            echo "$out"
            return
        fi
        sleep 1
    done
    echo "transaction $hash was not included" >&2
    exit 1
}

broadcast() {
    local out
    out=$("$@")
    local code
    code=$(echo "$out" | jq -r .code)
    if [ "$code" != 0 ]; then
        echo "$out" | jq -r .raw_log >&2
        exit 1
    fi
    wait_tx "$(echo "$out" | jq -r .txhash)"
}

# Sign and broadcast a transaction carrying the messages in $1 (a JSON list).
send_msgs() {
    local msgs=$1 tx=$WORK/tx.json
    "$SIMD" tx bank send relayer "$(addr)" 1stake "${TXF[@]}" --generate-only >"$tx"
    jq --argjson m "$msgs" '.body.messages = $m' "$tx" >"$tx.1"
    "$SIMD" tx sign "$tx.1" --from relayer --chain-id "$COSMOS_CHAIN_ID" --node "$NODE" "${KR[@]}" --output-document "$tx.2"
    broadcast "$SIMD" tx broadcast "$tx.2" --node "$NODE" --output json
}

b64() { printf '%s' "$1" | base64 -w0; }

hexarray() { python3 -c "import sys;print(list(bytes.fromhex(sys.argv[1][2:] if sys.argv[1].startswith('0x') else sys.argv[1])))" "$1"; }

stage_chain() {
    mkdir -p "$WORK"
    rm -rf "$HOME_DIR"
    "$SIMD" init local --chain-id "$COSMOS_CHAIN_ID" --home "$HOME_DIR" >/dev/null 2>&1
    "$SIMD" keys add relayer "${KR[@]}" >/dev/null 2>&1
    "$SIMD" genesis add-genesis-account relayer 100000000000000stake "${KR[@]}"
    "$SIMD" genesis gentx relayer 1000000000stake --chain-id "$COSMOS_CHAIN_ID" "${KR[@]}" >/dev/null 2>&1
    "$SIMD" genesis collect-gentxs --home "$HOME_DIR" >/dev/null 2>&1
    local g=$HOME_DIR/config/genesis.json
    jq '.app_state.gov.params.voting_period = "8s"
        | .app_state.gov.params.expedited_voting_period = "4s"
        | .app_state.gov.params.min_deposit = [{"denom":"stake","amount":"1000"}]
        | .app_state.gov.params.expedited_min_deposit = [{"denom":"stake","amount":"2000"}]' "$g" >"$g.1" && mv "$g.1" "$g"
    local c=$HOME_DIR/config/config.toml a=$HOME_DIR/config/app.toml
    sed -i "s|^laddr = \"tcp://127.0.0.1:26657\"|laddr = \"tcp://127.0.0.1:$RPC_PORT\"|;
            s|^laddr = \"tcp://0.0.0.0:26656\"|laddr = \"tcp://127.0.0.1:$P2P_PORT\"|;
            s|^timeout_commit = .*|timeout_commit = \"1s\"|;
            s|^pprof_laddr = .*|pprof_laddr = \"\"|" "$c"
    sed -i "s|^address = \"localhost:9090\"|address = \"127.0.0.1:$GRPC_PORT\"|;
            s|^minimum-gas-prices = .*|minimum-gas-prices = \"0stake\"|" "$a"
    sed -i '/^\[api\]/,/^\[/ s|^enable = .*|enable = false|' "$a"
    nohup "$SIMD" start --home "$HOME_DIR" >"$WORK/cosmos.log" 2>&1 &
    echo $! >"$WORK/cosmos.pid"
    wait_height 2
    log "chain up"
}

stage_anchor() {
    local h
    h=$(height)
    echo "$h $(crpc commit "{\"height\":\"$h\"}" | jq -r .result.signed_header.commit.block_id.hash)"
}

stage_cosmos() {
    mkdir -p "$WORK"
    [ -f "$WASM" ] || { echo "build the light client first: cargo build --release --lib --target wasm32-unknown-unknown in contracts/cosmos" >&2; exit 1; }
    # The chain's VM takes WebAssembly 1.0 only: lower the bulk-memory,
    # sign-extension and saturating-conversion instructions current Rust emits.
    "$WASM_OPT" -Oz --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int \
        --llvm-memory-copy-fill-lowering --signext-lowering --llvm-nontrapping-fptoint-lowering \
        "$WASM" -o "$WORK/light_client.wasm"
    local me
    me=$(addr)
    log "relayer $me"

    log "store the light client by governance"
    broadcast "$SIMD" tx ibc-wasm store-code "$WORK/light_client.wasm" --title tenzro --summary "Tenzro light client" --deposit 10000stake --from relayer "${TXF[@]}" --gas 200000000 >/dev/null
    local id
    id=$("$SIMD" q gov proposals --node "$NODE" --output json | jq -r '.proposals[-1].id')
    broadcast "$SIMD" tx gov vote "$id" yes --from relayer "${TXF[@]}" >/dev/null
    until [ "$("$SIMD" q gov proposal "$id" --node "$NODE" --output json | jq -r '.proposal.status')" = PROPOSAL_STATUS_PASSED ]; do sleep 1; done
    local checksum
    checksum=$("$SIMD" q ibc-wasm checksums --node "$NODE" --output json | jq -r '.checksums[0]')
    echo "$checksum" >"$WORK/checksum"
    log "checksum $checksum"

    log "create the Tenzro clients"
    local now_ms client consensus
    now_ms=$(( $(date +%s) * 1000 ))
    client=$(jq -cn --argjson img "$(hexarray "$FINALITY_IMAGE_ID")" --argjson gh "$(hexarray "$TENZRO_GENESIS_HASH")" \
        --argjson cr "$(hexarray "$TENZRO_COMMITTEE_ROOT")" --argjson cid "$TENZRO_CHAIN_ID" \
        '{image_id:$img, chain_id:$cid, genesis_hash:$gh, genesis_committee_root:$cr, latest_height:1, latest_index:0, frozen:false}')
    consensus=$(jq -cn --argjson ts "$now_ms" '{index:0, checkpoint_digest:[range(32)|0], state_root:[range(32)|0], timestamp_ms:$ts}')
    local checksum_b64
    checksum_b64=$(echo "$checksum" | xxd -r -p | base64 -w0)
    jq -n --arg d "$(b64 "$client")" --arg c "$checksum_b64" \
        '{"@type":"/ibc.lightclients.wasm.v1.ClientState", data:$d, checksum:$c, latest_height:{revision_number:"0", revision_height:"1"}}' >"$WORK/client_state.json"
    jq -n --arg d "$(b64 "$consensus")" '{"@type":"/ibc.lightclients.wasm.v1.ConsensusState", data:$d}' >"$WORK/consensus_state.json"
    for _ in classic v2; do
        broadcast "$SIMD" tx ibc client create "$WORK/client_state.json" "$WORK/consensus_state.json" --from relayer "${TXF[@]}" >/dev/null
    done
    log "clients 08-wasm-0 (classic) and 08-wasm-1 (v2)"

    log "classic: ConnOpenInit and ChanOpenInit towards Tenzro's identifiers"
    send_msgs "$(jq -cn --arg s "$me" --arg cp "07-tendermint-$(idnum "$ROUTE_CLASSIC")" '[{
        "@type":"/ibc.core.connection.v1.MsgConnectionOpenInit", client_id:"08-wasm-0",
        counterparty:{client_id:$cp, connection_id:"", prefix:{key_prefix:"aWJj"}},
        version:null, delay_period:"0", signer:$s}]')" >/dev/null
    send_msgs "$(jq -cn --arg s "$me" '[{
        "@type":"/ibc.core.channel.v1.MsgChannelOpenInit", port_id:"transfer",
        channel:{state:"STATE_INIT", ordering:"ORDER_UNORDERED", counterparty:{port_id:"transfer", channel_id:""},
                 connection_hops:["connection-0"], version:"ics20-1"}, signer:$s}]')" >/dev/null

    log "v2: register Tenzro as the counterparty of 08-wasm-1"
    send_msgs "$(jq -cn --arg s "$me" --arg cp "07-tendermint-$(idnum "$ROUTE_V2")" '[{
        "@type":"/ibc.core.client.v2.MsgRegisterCounterparty", client_id:"08-wasm-1",
        counterparty_merkle_prefix:["aWJj",""], counterparty_client_id:$cp, signer:$s}]')" >/dev/null

    log "v2: send one packet towards Tenzro"
    local timeout value
    timeout=$(( $(date +%s) + 3600 ))
    value=$(jq -cn --arg s "$me" '{denom:"stake", amount:"100", sender:$s, receiver:("0x" + ("77" * 32))}')
    echo "$value" >"$WORK/v2_packet_value.json"
    echo "$timeout" >"$WORK/v2_packet_timeout"
    send_msgs "$(jq -cn --arg s "$me" --arg v "$(b64 "$value")" --arg t "$timeout" '[{
        "@type":"/ibc.core.channel.v2.MsgSendPacket", source_client:"08-wasm-1", timeout_timestamp:$t,
        payloads:[{source_port:"transfer", destination_port:"transfer", version:"ics20-1", encoding:"application/json", value:$v}],
        signer:$s}]')" >/dev/null
    log "cosmos stage done at height $(height)"
}

# One CometBFT JSON-RPC call.
crpc() { curl -s "$RPC_URL" -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"; }

abci() {
    local key_hex=$1 h=$2
    crpc abci_query "{\"path\":\"store/ibc/key\",\"data\":\"$key_hex\",\"height\":\"$h\",\"prove\":true}"
}

stage_record() {
    local h trusted
    h=$(height)
    wait_height $((h + 2))
    trusted=$((h - 3))
    local target=$((h + 1))
    local v2_commit v2_receipt
    v2_commit=$(printf '08-wasm-1' | xxd -p)01$(printf '%016x' 1)
    v2_receipt=$(printf '08-wasm-1' | xxd -p)02$(printf '%016x' 1)
    jq -n \
        --arg chain_id "$COSMOS_CHAIN_ID" \
        --argjson trusted "$(crpc commit "{\"height\":\"$trusted\"}")" \
        --argjson target "$(crpc commit "{\"height\":\"$target\"}")" \
        --argjson target_validators "$(crpc validators "{\"height\":\"$target\"}")" \
        --argjson trusted_next_validators "$(crpc validators "{\"height\":\"$((trusted + 1))\"}")" \
        --argjson connection "$(abci "$(printf 'connections/connection-0' | xxd -p -c 256)" $((target - 1)))" \
        --argjson channel "$(abci "$(printf 'channelEnds/ports/transfer/channels/channel-0' | xxd -p -c 256)" $((target - 1)))" \
        --argjson v2_commitment "$(abci "$v2_commit" $((target - 1)))" \
        --argjson v2_receipt "$(abci "$v2_receipt" $((target - 1)))" \
        --arg v2_value "$(cat "$WORK/v2_packet_value.json")" \
        --arg v2_timeout "$(cat "$WORK/v2_packet_timeout")" \
        --arg classic_route "$ROUTE_CLASSIC" --arg v2_route "$ROUTE_V2" --arg v2_number "$(idnum "$ROUTE_V2")" \
        '{chain_id:$chain_id, classic_route:$classic_route, v2_route:$v2_route,
          trusted:$trusted, target:$target, target_validators:$target_validators.result.validators,
          trusted_next_validators:$trusted_next_validators.result.validators,
          connection:$connection, channel:$channel, v2_commitment:$v2_commitment, v2_receipt:$v2_receipt,
          v2_packet:{sequence:1, source_client:"08-wasm-1", destination_client:("07-tendermint-" + $v2_number),
                     timeout_timestamp:($v2_timeout|tonumber), value:$v2_value}}' >"$FIXTURE"
    log "recorded heights $trusted and $target into $FIXTURE"
}

# ---- round trip (GPU) ----

tz() { "$TENZRO" "$@"; }

# Run a tenzro command that sends one transaction until that transaction
# executes. A validator's node account also carries its node's own records,
# and a transaction of the account ordered out of nonce order fails without
# spending anything, so it is sent again at the next free nonce.
send_executed() {
    local out hash status
    for _ in $(seq 10); do
        out=$(tz "$@" | sed 's/\x1b\[[0-9;]*m//g') || true
        echo "$out" >&2
        hash=$(echo "$out" | awk '$1 == "Transaction" && $2 == "Hash" {print $3}' | tail -n 1)
        [ -n "$hash" ] || { sleep 5; continue; }
        for _ in $(seq 150); do
            status=$(curl -s "$TENZRO_RPC" -H 'content-type: application/json' \
                -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"0x${hash#0x}\"]}" | jq -r '.result.status // empty')
            [ -n "$status" ] && break
            sleep 2
        done
        [ "$status" = 0x1 ] && return 0
        sleep 5
    done
    echo "the transaction did not execute: tenzro $*" >&2
    return 1
}

# Install the IBC routes by governance: the first validator's node account
# proposes each, every validator votes as its machine root, and a client
# enacts each once its voting period and timelock have run (a route is
# installed on the standard track, so this waits that long; both routes are
# proposed and voted first so their periods run together).
# `validator register-machine` registers each machine identity once (the
# vote needs it) and names the validator account the ballot carries.
propose_route() {
    local route_json=$1 id before
    before=$(tz governance list --json --limit 1 --rpc "$TENZRO_RPC" | jq -r '.proposals[0].proposal.id // "null"')
    send_executed governance propose --node-account --key-namespace "${VOTERS%% *}" --rpc "$TENZRO_RPC" \
        --action "$(jq -cn --argjson r "$route_json" '{action:"set_bridge_route", route:$r, memo:"local IBC round trip"}')" || return 1
    id=$(tz governance list --json --limit 1 --rpc "$TENZRO_RPC" | jq -r '.proposals[0].proposal.id // "null"')
    [ "$id" != null ] && [ "$id" != "$before" ] || { echo "the route proposal is not listed" >&2; return 1; }
    echo "$id"
}

vote_route() {
    local id=$1 v validator
    for v in $VOTERS; do
        validator=$(tz validator register-machine --key-namespace "$v" --rpc "$TENZRO_RPC" | sed 's/\x1b\[[0-9;]*m//g' | awk '$1 == "Wallet" {print $2}')
        send_executed governance vote "$id" --machine-root --key-namespace "$v" --validator "$validator" --yes --rpc "$TENZRO_RPC" || return 1
    done
}

enact_route() {
    local id=$1
    log "enact proposal $id once its voting period and timelock have run"
    until send_executed governance execute "$id" --key-namespace "$EXECUTOR_KEY_NAMESPACE" --rpc "$TENZRO_RPC" 2>/dev/null; do
        sleep 600
    done
    log "proposal $id enacted"
}

ibc_route_json() {
    local name=$1 version=$2 cp_client=$3 cp_conn=$4 cp_chan=$5 trusted_height=$6 trusted_hash=$7
    python3 - "$name" "$version" "$cp_client" "$cp_conn" "$cp_chan" "$trusted_height" "$trusted_hash" "$COSMOS_CHAIN_ID" "$ROUTE_VERIFIERS" <<'EOF'
import hashlib, json, sys
name, version, cp_client, cp_conn, cp_chan, th, thash, chain_id, verifiers = sys.argv[1:]
cp_id = cp_chan if version == "classic" else cp_client
n = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big")
own = f"channel-{n}" if version == "classic" else f"07-tendermint-{n}"
h = lambda s: list(hashlib.sha256(s.encode()).digest())
ramp = list(b"ibc") + [0] * 29
route = {
  "adapter": "ibc", "family": "cosmos", "source_chain": name,
  "source_chain_id": "118", "local_selector": "7777",
  "peer": h(f"transfer/{cp_id}"), "ramp": ramp, "local_endpoint": h(f"transfer/{own}"),
  "remote_token": h(f"transfer/{cp_id}/atnzo"),
  "verifiers": json.loads(verifiers),
  "blessing": None,
  "light_client": {"tendermint": {"chain_id": chain_id, "trusted_height": int(th), "trusted_header_hash": list(bytes.fromhex(thash)), "trusting_period_secs": 1209600}},
  "mint_limit": {"per_mint": "1000000000000000000000", "per_epoch": "10000000000000000000000"},
  "outflow": {"capacity": "10000000000000000000000", "rate": "1000000000000000000"},
  "lane_limits": None,
  "ibc": {"version": version, "counterparty_client_id": cp_client,
          "counterparty_connection_id": cp_conn if version == "classic" else None,
          "counterparty_channel_id": cp_chan if version == "classic" else None,
          "packet_timeout_secs": 600},
}
print(json.dumps(route))
EOF
}

# A Groth16 finality proof of Tenzro's latest checkpoint, sent to the Cosmos
# client `$1`. Prints the Tenzro state height the client now holds.
update_tenzro_client() {
    local client=$1 step=$WORK/step.bin receipt=$WORK/receipt.bin proof=$WORK/proof.json
    tz finality step --chain-id "$TENZRO_CHAIN_ID" --genesis-hash "$TENZRO_GENESIS_HASH" --out "$step" --rpc "$TENZRO_RPC" >&2
    "$PROVER_STARK" stark --step "$step" --out "$receipt" >&2
    "$PROVER_WRAP" wrap --receipt "$receipt" --out "$proof" >&2
    local message
    message=$(jq -r '.journal + .seal' "$proof" | xxd -r -p | base64 -w0)
    send_msgs "$(jq -cn --arg s "$(addr)" --arg c "$client" --arg m "$message" '[{
        "@type":"/ibc.core.client.v1.MsgUpdateClient", client_id:$c,
        client_message:{"@type":"/ibc.lightclients.wasm.v1.ClientMessage", data:$m}, signer:$s}]')" >/dev/null
    "$SIMD" q ibc client state "$client" --node "$NODE" --output json | jq -r '.client_state.latest_height.revision_height'
}

# The Tenzro state proof (base64 JSON) of IBC store entry $1 (hex path) at
# Tenzro height $2, as the Cosmos client verifies it.
tenzro_proof() {
    local path_hex=$1 h=$2 entry
    entry=$(python3 -c "import sys;p=sys.argv[1];e='ibc/'+p;print(('storage:'+'ff'*20+':'+e.encode().hex()).encode().hex())" "$path_hex")
    curl -s "$TENZRO_RPC" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tenzro_getStateProof\",\"params\":{\"namespace\":\"state\",\"key\":\"$entry\",\"height\":$h}}" \
        | jq -c .result.proof | tr -d '\n' | base64 -w0
}

# Run a tenzro command that submits one transaction and wait until a block
# has executed it: what the next step reads (a light-client head, a
# connection or channel end, an outbound packet) exists only from then on.
# With --ok the transaction must also have succeeded.
tz_executed() {
    local need_ok=
    [ "$1" = --ok ] && { need_ok=1; shift; }
    local out hash status=
    out=$(tz "$@" | sed 's/\x1b\[[0-9;]*m//g')
    echo "$out"
    hash=$(echo "$out" | awk '($1 == "Tx" || $1 == "Transaction") && $2 == "Hash" {print $3}' | tail -n 1)
    [ -n "$hash" ] || { echo "no transaction hash from: tenzro $*" >&2; return 1; }
    for _ in $(seq 150); do
        status=$(curl -s "$TENZRO_RPC" -H 'content-type: application/json' \
            -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"0x${hash#0x}\"]}" | jq -r '.result.status // empty')
        [ -n "$status" ] && break
        sleep 2
    done
    [ -n "$status" ] || { echo "transaction $hash was not executed in 300 s: tenzro $*" >&2; return 1; }
    [ "$status" = 0x1 ] || { echo "transaction $hash reverted: tenzro $*" >&2; [ -z "$need_ok" ]; }
}

# A header the light client already holds is refused on chain, so a relay
# only waits for its transaction; an IBC message must succeed.
relay_lc() { tz_executed bridge light-client --adapter ibc --chain "$1" --cosmos-rpc "$RPC_URL" --key-namespace "$KEY_NAMESPACE" --rpc "$TENZRO_RPC"; }

relay_ibc() { local chain=$1; shift; tz_executed --ok bridge ibc --chain "$chain" --cosmos-rpc "$RPC_URL" --key-namespace "$KEY_NAMESPACE" --rpc "$TENZRO_RPC" "$@"; }

outbound_packet() { curl -s "$TENZRO_RPC" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tenzro_getBridgeOutbound\",\"params\":{\"adapter\":\"ibc\",\"source_chain\":\"$1\",\"sequence\":$2}}" | jq -c .result; }

recv_on_cosmos() {
    local route=$1 version=$2 client=$3 seq=$4 h=$5 out path proof
    out=$(outbound_packet "$route" "$seq")
    path=$(echo "$out" | jq -r .packet.commitment_path | sed 's/^0x//')
    proof=$(tenzro_proof "$path" "$h")
    python3 - "$version" "$(echo "$out" | jq -r .message)" "$proof" "$h" "$(addr)" >"$WORK/recv.json" <<'EOF'
import base64, json, sys
version, msg_hex, proof, h, signer = sys.argv[1:]
b = bytes.fromhex(msg_hex[2:])
o = 0
def take(n):
    global o; v = b[o:o+n]; o += n; return v
u64 = lambda: int.from_bytes(take(8), "big")
s16 = lambda: take(int.from_bytes(take(2), "big")).decode()
seq = u64(); sp, sc, dp, dc = s16(), s16(), s16(), s16()
data = take(int.from_bytes(take(4), "big")); rn, rh, ts = u64(), u64(), u64()
height = {"revision_number": "0", "revision_height": h}
if version == "classic":
    m = {"@type": "/ibc.core.channel.v1.MsgRecvPacket",
         "packet": {"sequence": str(seq), "source_port": sp, "source_channel": sc, "destination_port": dp, "destination_channel": dc,
                    "data": base64.b64encode(data).decode(), "timeout_height": {"revision_number": str(rn), "revision_height": str(rh)},
                    "timeout_timestamp": str(ts)},
         "proof_commitment": proof, "proof_height": height, "signer": signer}
else:
    m = {"@type": "/ibc.core.channel.v2.MsgRecvPacket",
         "packet": {"sequence": str(seq), "source_client": sc, "destination_client": dc, "timeout_timestamp": str(ts),
                    "payloads": [{"source_port": sp, "destination_port": dp, "version": "ics20-1", "encoding": "application/json",
                                  "value": base64.b64encode(data).decode()}]},
         "proof_commitment": proof, "proof_height": height, "signer": signer}
print(json.dumps([m]))
EOF
    send_msgs "$(cat "$WORK/recv.json")"
}

stage_routes() {
    : "${TENZRO:?}" "${TENZRO_RPC:?}" "${VOTERS:?}" "${EXECUTOR_KEY_NAMESPACE:?}" "${ROUTE_VERIFIERS:?}"
    local trusted thash
    read -r trusted thash < <(stage_anchor)
    log "install the routes by governance"
    local p_classic p_v2
    p_classic=$(propose_route "$(ibc_route_json "$ROUTE_CLASSIC" classic 08-wasm-0 connection-0 channel-0 "$trusted" "$thash")")
    p_v2=$(propose_route "$(ibc_route_json "$ROUTE_V2" v2 08-wasm-1 "" "" "$trusted" "$thash")")
    vote_route "$p_classic"
    vote_route "$p_v2"
    enact_route "$p_classic"
    enact_route "$p_v2"
}

stage_round_trip() {
    : "${TENZRO:?}" "${TENZRO_RPC:?}" "${PROVER_STARK:?}" "${PROVER_WRAP:?}" "${KEY_NAMESPACE:?}" "${SENDER_KEY_NAMESPACE:?}"
    local me
    me=$(addr)
    for r in "$ROUTE_CLASSIC" "$ROUTE_V2"; do relay_lc "$r"; relay_lc "$r"; done

    log "classic: ConnOpenTry on Tenzro, ConnOpenAck on Cosmos, ConnOpenConfirm on Tenzro"
    relay_ibc "$ROUTE_CLASSIC" --message connection-open-try
    local th conn chan
    conn="connection-$(idnum "$ROUTE_CLASSIC")"
    chan="channel-$(idnum "$ROUTE_CLASSIC")"
    th=$(update_tenzro_client 08-wasm-0)
    send_msgs "$(jq -cn --arg s "$me" --arg c "$conn" --arg p "$(tenzro_proof "$(printf 'connections/%s' "$conn" | xxd -p -c 256)" "$th")" --arg h "$th" '[{
        "@type":"/ibc.core.connection.v1.MsgConnectionOpenAck", connection_id:"connection-0", counterparty_connection_id:$c,
        version:{identifier:"1", features:["ORDER_ORDERED","ORDER_UNORDERED"]},
        proof_try:$p, proof_height:{revision_number:"0", revision_height:$h}, signer:$s}]')" >/dev/null
    relay_lc "$ROUTE_CLASSIC"
    relay_ibc "$ROUTE_CLASSIC" --message connection-open-confirm

    log "classic: ChanOpenTry on Tenzro, ChanOpenAck on Cosmos, ChanOpenConfirm on Tenzro"
    relay_ibc "$ROUTE_CLASSIC" --message channel-open-try
    th=$(update_tenzro_client 08-wasm-0)
    send_msgs "$(jq -cn --arg s "$me" --arg c "$chan" --arg p "$(tenzro_proof "$(printf 'channelEnds/ports/transfer/channels/%s' "$chan" | xxd -p -c 256)" "$th")" --arg h "$th" '[{
        "@type":"/ibc.core.channel.v1.MsgChannelOpenAck", port_id:"transfer", channel_id:"channel-0",
        counterparty_channel_id:$c, counterparty_version:"ics20-1",
        proof_try:$p, proof_height:{revision_number:"0", revision_height:$h}, signer:$s}]')" >/dev/null
    relay_lc "$ROUTE_CLASSIC"
    relay_ibc "$ROUTE_CLASSIC" --message channel-open-confirm

    for pair in "$ROUTE_CLASSIC:classic:08-wasm-0" "$ROUTE_V2:v2:08-wasm-1"; do
        IFS=: read -r route version client <<<"$pair"
        log "$version: send TNZO out twice; receive and acknowledge the first, time out the second"
        tz_executed --ok bridge send --target-chain "$route" --recipient "$(printf '%s' "$me" | xxd -p -c 256)" --amount 1000000000000000000 --key-namespace "$SENDER_KEY_NAMESPACE" --rpc "$TENZRO_RPC"
        tz_executed --ok bridge send --target-chain "$route" --recipient "$(printf '%s' "$me" | xxd -p -c 256)" --amount 2000000000000000000 --key-namespace "$SENDER_KEY_NAMESPACE" --rpc "$TENZRO_RPC"
        th=$(update_tenzro_client "$client")
        recv_on_cosmos "$route" "$version" "$client" 1 "$th"
        relay_lc "$route"
        # The transfer module's success acknowledgement, in both versions.
        relay_ibc "$route" --message acknowledge --sequence 1 --acknowledgement "$(printf '{"result":"AQ=="}' | xxd -p -c 256)"
        log "$version: wait past the second packet's timeout, then time it out"
        sleep 660
        relay_lc "$route"
        relay_ibc "$route" --message timeout --sequence 2
        [ "$(outbound_packet "$route" 1 | jq -r .packet.status)" = settled ]
        [ "$(outbound_packet "$route" 2 | jq -r .packet.status)" = settled ]
        log "$version: round trip complete"
    done
}

stage_stop() {
    if [ -f "$WORK/cosmos.pid" ]; then
        kill "$(cat "$WORK/cosmos.pid")" 2>/dev/null || true
        rm -f "$WORK/cosmos.pid"
    fi
}

case "$STAGE" in
    chain) stage_chain ;;
    anchor) stage_anchor ;;
    cosmos) stage_cosmos ;;
    record) stage_record ;;
    routes) stage_routes ;;
    round-trip) stage_round_trip ;;
    stop) stage_stop ;;
    *) sed -n '2,52p' "$0"; exit 2 ;;
esac
