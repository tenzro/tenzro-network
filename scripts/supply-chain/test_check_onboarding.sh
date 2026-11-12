#!/bin/bash
# Test for check-onboarding.sh: it passes on the repository, and fails when a new node flag, node
# subcommand or environment variable appears without an entry in onboarding-entry-points.txt, when
# an installer or package script starts, sets up or joins anything, and when a test-only key
# feature is made a default or is turned on by a release build. Each case works on a copy of the
# checked files in a temporary tree.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
check=$here/check-onboarding.sh
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
failures=0
expect() { # name expected-rc root [expected-text]
  ONBOARD_ROOT=$3 ONBOARD_LIST=$here/onboarding-entry-points.txt bash "$check" > "$tmp/out" 2>&1; rc=$?
  if [ "$rc" -ne "$2" ]; then echo "FAIL $1: exit $rc, wanted $2"; sed 's/^/  /' "$tmp/out"; failures=$((failures + 1))
  elif [ -n "${4:-}" ] && ! grep -q -- "$4" "$tmp/out"; then echo "FAIL $1: output does not name '$4'"; sed 's/^/  /' "$tmp/out"; failures=$((failures + 1))
  else echo "ok   $1"; fi
}
fresh() {
  rm -rf "$tmp/t"; mkdir -p "$tmp/t"
  (cd "$repo" && tar -c crates/tenzro-node/src/main.rs crates/tenzro-cli/src/main.rs scripts/install packaging/linux/deb packaging/macos/scripts packaging/common packaging/linux/rpm Dockerfile $(find crates sdk apps -name Cargo.toml -not -path '*/target/*' -not -path '*/node_modules/*')) | tar -x -C "$tmp/t"
}

expect "repository passes" 0 "$repo"
fresh; expect "copy passes" 0 "$tmp/t"
fresh; sed -i '0,/#\[arg(long)\]/s//#[arg(long)]\n    skip_identity: bool,\n    #[arg(long)]/' "$tmp/t/crates/tenzro-node/src/main.rs"; expect "new node flag" 1 "$tmp/t" "--skip-identity"
fresh; sed -i 's/^    #\[command(name = "hardware")\]/    #[command(name = "unlock")]\n    Unlock,\n    #[command(name = "hardware")]/' "$tmp/t/crates/tenzro-node/src/main.rs"; expect "new node subcommand" 1 "$tmp/t" "subcommand unlock"
fresh; sed -i '1i fn f() { let _ = std::env::var("TENZRO_ALLOW_SOFTWARE_KEY"); }' "$tmp/t/crates/tenzro-cli/src/main.rs"; expect "new env var in non-test code" 1 "$tmp/t" "TENZRO_ALLOW_SOFTWARE_KEY"
fresh; sed -i '1i #[cfg(test)]\nmod t { fn f() { let _ = std::env::var("TENZRO_FIXTURE_ONLY"); } }' "$tmp/t/crates/tenzro-cli/src/main.rs"; expect "new env var in test code" 0 "$tmp/t"
fresh; printf '"$X/bin/tenzro" setup --apply --yes\n' >> "$tmp/t/scripts/install/install.sh"; expect "installer runs setup" 1 "$tmp/t" "install.sh"
fresh; printf 'systemctl enable --now tenzro-node\n' >> "$tmp/t/packaging/linux/deb/postinst"; expect "package enables the service" 1 "$tmp/t" "postinst"
fresh; printf '"$X/bin/tenzro-node" --solo --roles validator\n' >> "$tmp/t/scripts/install/install.sh"; expect "installer starts a solo node" 1 "$tmp/t" "install.sh"
fresh; printf 'echo "run: tenzro setup, then tenzro join"\nsay "tenzro dev starts a chain"\n' >> "$tmp/t/scripts/install/install.sh"; expect "installer only mentions commands" 0 "$tmp/t"
fresh; printf '\n[features]\ndefault = ["inference", "test-passkey"]\n' >> "$tmp/t/crates/tenzro-node/Cargo.toml"; expect "test feature in default" 1 "$tmp/t" "default feature set"
fresh; printf 'RUN cargo build --release --features test-signer\n' >> "$tmp/t/Dockerfile"; expect "container build turns on a test feature" 1 "$tmp/t" "test-only feature"
[ $failures -eq 0 ] && echo "all cases passed" || { echo "$failures case(s) failed"; exit 1; }
