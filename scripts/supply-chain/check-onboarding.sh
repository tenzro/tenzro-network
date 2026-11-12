#!/bin/bash
# R35, onboarding cannot be bypassed: refuse a NEW way to start a participant, register a role,
# stake, accept a grant or serve that has not been looked at. Every `tenzro-node` start flag and
# subcommand, every TENZRO_* environment variable read by non-test code, and every file that
# installs Tenzro must be in onboarding-entry-points.txt with the reason it cannot let anything
# act without a hardware-rooted wallet and identity (TPM, delegated TPM, Secure Enclave, passkey).
# A new one fails this check until someone writes that reason down. The CLI's own command tree is
# guarded by the test in crates/tenzro-cli/src/onboarding_guard.rs, and the node's start verdict by
# crates/tenzro-node/tests/onboarding_guard.rs.
#
# Also refused: an installer or package script that starts, enables, sets up, joins or stakes
# anything; a Cargo `default` feature set that carries a test-only key feature; a release, package
# or container build that turns one on.
#
# ONBOARD_ROOT overrides the tree to check (used by test_check_onboarding.sh).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=${ONBOARD_ROOT:-$(cd "$here/../.." && pwd)}
list=${ONBOARD_LIST:-$here/onboarding-entry-points.txt}
cd "$root" || exit 2
fail=0
bad() { echo "$1"; fail=1; }

allowed() { grep -v -E '^[[:space:]]*(#|$)' "$list" | awk -v k="$1" '$1 == k {print $2}' | sort -u; }

# 1. Environment variables read by non-test Rust code.
files=$(find crates sdk apps -name '*.rs' -not -path '*/target/*' -not -path '*/node_modules/*' 2>/dev/null \
  | grep -v -E '/(tests|benches|examples)/|test_support|tests\.rs$' | sort)
current_env=$(for f in $files; do
  awk -v F="$f" '/#\[cfg\(test\)\]/ {exit} {l=$0; while (match(l, /"TENZRO_[A-Z0-9_]+"/)) {print substr(l, RSTART+1, RLENGTH-2), F; l=substr(l, RSTART+RLENGTH)}}' "$f"
done | sort -u)
known_env=$(allowed env)
while read -r name file; do
  [ -z "$name" ] && continue
  printf '%s\n' "$known_env" | grep -qx "$name" || bad "new environment variable $name read in $file: add 'env $name <why it cannot skip the hardware-rooted identity>' to onboarding-entry-points.txt"
done <<< "$current_env"

# 2. tenzro-node start flags and subcommands (crates/tenzro-node/src/main.rs).
main=crates/tenzro-node/src/main.rs
if [ -f "$main" ]; then
  flags=$(awk '
    function kebab(s) { gsub(/_/, "-", s); return s }
    /#\[arg\(/ {inarg=1; attr=""}
    inarg {attr = attr " " $0; if ($0 ~ /\)\]/) {inarg=0; pend=1}; next}
    pend && /^[[:space:]]*(\/\/\/|#\[)/ {next}
    pend {
      pend=0
      if (attr !~ /long/) next
      name=""
      if (match(attr, /long *= *"[^"]+"/)) { t=substr(attr, RSTART, RLENGTH); sub(/^long *= *"/, "", t); sub(/"$/, "", t); name=t }
      else if (match($0, /^[[:space:]]*(pub )?[a-z_0-9]+:/)) { t=substr($0, RSTART, RLENGTH); gsub(/^[[:space:]]*(pub )?/, "", t); sub(/:$/, "", t); name=kebab(t) }
      if (name != "") print "--" name
    }' "$main" | sort -u)
  subs=$(awk '
    function kebab(s,   o, i, c) { o=""; for (i=1; i<=length(s); i++) { c=substr(s, i, 1); if (c ~ /[A-Z]/) { if (i>1) o=o "-"; o=o tolower(c) } else o=o c }; return o }
    /^(pub )?enum (Command|[A-Za-z]*Action|[A-Za-z]*Cmd|[A-Za-z]*Commands?) *\{/ {inenum=1; en=$0; sub(/^(pub )?enum /, "", en); sub(/ .*/, "", en); next}
    inenum && /^\}/ {inenum=0}
    inenum && /#\[command\(name *= *"/ { match($0, /"[^"]+"/); nm=substr($0, RSTART+1, RLENGTH-2); next }
    inenum && /^    [A-Z][A-Za-z0-9]*( *\{|,|\()/ { v=$1; gsub(/[ {,(].*/, "", v); print (nm != "" ? nm : kebab(v)); nm="" }
  ' "$main" | sort -u)
  known_flag=$(allowed node-flag); known_sub=$(allowed node-sub)
  for f in $flags; do printf '%s\n' "$known_flag" | grep -qx -- "$f" || bad "new tenzro-node flag $f in $main: add 'node-flag $f <why it cannot start a participant before the hardware-identity gate>' to onboarding-entry-points.txt"; done
  for s in $subs; do printf '%s\n' "$known_sub" | grep -qx -- "$s" || bad "new tenzro-node subcommand $s in $main: add 'node-sub $s <what it does and why it needs the hardware root or is read-only>' to onboarding-entry-points.txt"; done
fi

# 3. Installer and package scripts start, enable, set up, join and stake nothing. Message lines
# (echo, say, printf, note, row, Write-Host, fail) and comments are not commands.
scripts="scripts/install/install.sh scripts/install/install.ps1 packaging/linux/deb/postinst packaging/linux/deb/postrm packaging/macos/scripts/postinstall packaging/macos/build-pkg.sh packaging/common/tenzro-check packaging/linux/rpm/tenzro.spec.in"
cmd='(^|[ ;&|(`"])(\$[A-Za-z_{}]+/bin/|/[^ ]*/)?tenzro(-node)?(\.exe)?"?[ ]+(setup|join|dev|node[ ]+start|stake|validator|provider|--solo|--dev|--roles|--validator-self-stake|tpm[ ]+(provision|key-holder|grant-install))'
svc='systemctl[[:space:]]+(enable|start|restart|reload)|launchctl[[:space:]]+(load|bootstrap|kickstart|enable)|Start-Service|New-Service|sc(\.exe)?[[:space:]]+(create|start)|schtasks'
for s in $scripts; do
  [ -f "$s" ] || continue
  body=$(grep -v -E '^[[:space:]]*(#|//)|(^|[[:space:]]|\))(echo|say|printf|note|row|Write-Host|fail|Fail)[[:space:]]' "$s")
  hit=$(printf '%s\n' "$body" | grep -n -E "$cmd|$svc" | head -3)
  [ -n "$hit" ] && bad "$s starts, enables, sets up or joins something: $hit"
done

# 4. Test-only key features: never in a `default` set, never turned on by a release, package or
# container build.
tf='test-(passkey|signer|keys|ca|root|support)'
for t in $(find crates sdk apps -name Cargo.toml -not -path '*/target/*' -not -path '*/node_modules/*' 2>/dev/null); do
  hit=$(awk -v tf="$tf" '/^\[features\]/ {f=1; next} /^\[/ {f=0} f && /^default *=/ && $0 ~ tf {print FILENAME ":" FNR ": " $0}' "$t")
  [ -n "$hit" ] && bad "a test-only feature is in a default feature set: $hit"
done
for d in scripts/release packaging Dockerfile Dockerfile.cuda Dockerfile.rocm Dockerfile.vulkan scripts/build-tier.sh scripts/build-cuda-native.sh .github/workflows/release-macos.yml; do
  [ -e "$d" ] || continue
  hit=$(grep -rn -E "(--features|--all-features|features *[:=]).*($tf)|--all-features" "$d" 2>/dev/null | head -3)
  [ -n "$hit" ] && bad "a release, package or container build turns on a test-only feature: $hit"
done

if [ $fail -ne 0 ]; then echo "onboarding check FAILED"; exit 1; fi
echo "onboarding check passed"
