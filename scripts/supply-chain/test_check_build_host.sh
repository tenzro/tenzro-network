#!/usr/bin/env bash
# Tests check-build-host.sh and its use by scripts/test-runner.sh with a
# systemctl that reports the units named in ACTIVE as active.
set -u
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/empty" "$tmp/target/debug/deps"
cat > "$tmp/bin/systemctl" <<'SH'
#!/bin/sh
# systemctl <scope> is-active --quiet <unit>
case " $ACTIVE " in *" $1:$4 "*) exit 0 ;; esac
exit 3
SH
chmod +x "$tmp/bin/systemctl"
printf '#!/bin/sh\necho ran\n' > "$tmp/target/debug/deps/some_test-0123456789abcdef"
printf '#!/bin/sh\necho ran\n' > "$tmp/target/debug/tool"
chmod +x "$tmp/target/debug/deps/some_test-0123456789abcdef" "$tmp/target/debug/tool"
fail=0
check() { # want-rc want-stderr-pattern label env-or-arg...
  local want=$1 pat=$2 label=$3; shift 3
  local err; err=$(env PATH="$tmp/bin:$PATH" "$@" 2>&1 >/dev/null); local rc=$?
  [[ $rc == "$want" ]] || { echo "FAIL: $label: exit $rc, want $want"; fail=1; }
  if [[ -z $pat ]]; then [[ -z $err ]] || { echo "FAIL: $label: printed: $err"; fail=1; }
  else [[ $err == $pat ]] || { echo "FAIL: $label: printed: $err"; fail=1; }; fi
}
guard="$here/check-build-host.sh"
check 0 "" "no node service" ACTIVE= "$guard"
check 0 "warning: tenzro-node.service is active*" "a node service, builds not forbidden" ACTIVE=--system:tenzro-node.service "$guard"
check 0 "warning: tenzro-node.service is active*" "a user node service" ACTIVE=--user:tenzro-node.service "$guard"
check 0 "warning: tenzro-testnet-node.service is active*" "a testnet node service" ACTIVE=--system:tenzro-testnet-node.service "$guard"
check 0 "" "a node service, quiet" ACTIVE=--system:tenzro-node.service "$guard" --quiet
check 0 "" "another service" ACTIVE=--system:tenzro-model-worker.service "$guard"
check 1 "REFUSING: tenzro-node.service is active*" "a node service, builds forbidden by the environment" ACTIVE=--system:tenzro-node.service TENZRO_BUILD_GUARD=enforce "$guard"
check 0 "" "builds forbidden, no node service" ACTIVE= TENZRO_BUILD_GUARD=enforce "$guard"
# a machine without systemd
env PATH="$tmp/empty" /bin/sh "$guard" > /dev/null 2>&1 || { echo "FAIL: a machine without systemctl was refused"; fail=1; }
# the cargo runner beside a node service: test binaries and tools both run, silently
runner="$here/../test-runner.sh"
test_bin="$tmp/target/debug/deps/some_test-0123456789abcdef"
out=$(env PATH="$tmp/bin:$PATH" ACTIVE=--system:tenzro-node.service "$runner" "$test_bin" 2>&1)
[[ $out == ran ]] || { echo "FAIL: a test binary beside a node service: $out"; fail=1; }
# the operator's marker file forbids builds. The shipped guard names one fixed path; the cases run a
# copy of it, and of the runner that calls it, in which only that path is moved under $tmp.
grep -qx 'marker=/etc/tenzro/no-builds' "$guard" || { echo "FAIL: the guard does not name the marker /etc/tenzro/no-builds"; fail=1; }
mkdir -p "$tmp/copy/supply-chain" "$tmp/marked/etc/tenzro"
sed "s|^marker=/etc/tenzro/no-builds\$|marker=$tmp/marked/etc/tenzro/no-builds|" "$guard" > "$tmp/copy/supply-chain/check-build-host.sh"
cp "$runner" "$tmp/copy/test-runner.sh"
chmod +x "$tmp/copy/supply-chain/check-build-host.sh" "$tmp/copy/test-runner.sh"
grep -q "marker=$tmp/marked" "$tmp/copy/supply-chain/check-build-host.sh" || { echo "FAIL: the marker path could not be moved in the copy"; fail=1; }
: > "$tmp/marked/etc/tenzro/no-builds"
guard="$tmp/copy/supply-chain/check-build-host.sh"
runner="$tmp/copy/test-runner.sh"
check 1 "REFUSING: tenzro-node.service is active*" "a node service, builds forbidden by the marker" ACTIVE=--system:tenzro-node.service "$guard"
check 1 "REFUSING: *" "the marker, quiet" ACTIVE=--system:tenzro-node.service "$guard" --quiet
check 0 "" "the marker, no node service" ACTIVE= "$guard"
out=$(env PATH="$tmp/bin:$PATH" ACTIVE=--system:tenzro-node.service "$runner" "$test_bin" 2>/dev/null)
[[ $? == 1 && -z $out ]] || { echo "FAIL: a test binary ran where the operator forbids builds"; fail=1; }
out=$(env PATH="$tmp/bin:$PATH" ACTIVE=--system:tenzro-node.service "$runner" "$tmp/target/debug/tool" 2>/dev/null)
[[ $out == ran ]] || { echo "FAIL: a tool was refused beside a node service"; fail=1; }
[[ $fail == 0 ]] && echo "ok"
exit $fail
