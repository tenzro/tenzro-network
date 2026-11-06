#!/bin/bash
# Test for check-unsafe.sh: it passes on the repository, and fails when unsafe is added to a
# forbidden crate, added to consensus outside compact_work.rs, added to compact_work.rs, or when a
# forbid attribute is removed. Each case works on a copy of the checked sources in a temporary tree.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
check=$here/check-unsafe.sh
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
failures=0
expect() { # name expected-rc root
  UNSAFE_ROOT=$3 bash "$check" > "$tmp/out" 2>&1; rc=$?
  if [ "$rc" -ne "$2" ]; then echo "FAIL $1: exit $rc, wanted $2"; sed 's/^/  /' "$tmp/out"; failures=$((failures + 1)); else echo "ok   $1"; fi
}
fresh() { rm -rf "$tmp/t"; mkdir -p "$tmp/t"; (cd "$repo" && tar -c $(for c in tenzro-crypto tenzro-identity tenzro-iroh tenzro-zk tenzro-consensus; do echo crates/$c/src; done)) | tar -x -C "$tmp/t"; }

expect "repository passes" 0 "$repo"
fresh; expect "copy passes" 0 "$tmp/t"
fresh; printf 'fn f() { unsafe { } }\n' >> "$tmp/t/crates/tenzro-zk/src/lib.rs"; expect "unsafe in zk" 1 "$tmp/t"
fresh; printf 'fn f() { unsafe { } }\n' >> "$tmp/t/crates/tenzro-consensus/src/core.rs"; expect "unsafe in consensus core" 1 "$tmp/t"
fresh; printf 'fn f() { unsafe { } }\n' >> "$tmp/t/crates/tenzro-consensus/src/compact_work.rs"; expect "third unsafe in compact_work" 1 "$tmp/t"
fresh; sed -i '/^#!\[forbid(unsafe_code)\]/d' "$tmp/t/crates/tenzro-crypto/src/lib.rs"; expect "forbid removed" 1 "$tmp/t"
fresh; printf '// unsafe is discussed here\n' >> "$tmp/t/crates/tenzro-iroh/src/lib.rs"; expect "comment mentioning unsafe" 0 "$tmp/t"
[ $failures -eq 0 ] && echo "all cases passed" || { echo "$failures case(s) failed"; exit 1; }
