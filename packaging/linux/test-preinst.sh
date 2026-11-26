#!/bin/sh
# Runs packaging/linux/deb/preinst against a fake getconf: an old glibc is refused with the plain sentence,
# a new one and an unreadable one pass. No root, nothing installed.
set -u
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
fail=0
try() { # <glibc output or ""> <phase> <want rc> <label>
    printf '#!/bin/sh\n[ -n "%s" ] && echo "glibc %s" || exit 1\n' "$1" "$1" > "$t/getconf"; chmod +x "$t/getconf"
    out=$(PATH="$t:$PATH" sh "$here/deb/preinst" "$2" 2>&1); rc=$?
    [ "$rc" = "$3" ] && echo "ok   $4" || { echo "FAIL $4 (rc $rc, want $3): $out"; fail=1; }
    [ "$3" = 0 ] || case "$out" in *"Tenzro needs glibc 2.39 or newer"*"has glibc $1"*) ;; *) echo "FAIL $4: sentence: $out"; fail=1 ;; esac
}
try 2.36 install 1 "Debian 12 (2.36) refused"
try 2.35 upgrade 1 "Ubuntu 22.04 (2.35) refused on upgrade"
try 2.39 install 0 "Ubuntu 24.04 (2.39) accepted"
try 2.41 install 0 "newer accepted"
try 2.9  install 1 "2.9 is older than 2.39, not newer by string order"
try "" install 0 "unreadable glibc is not a refusal"
try 2.36 abort-upgrade 0 "other phases do nothing"
exit $fail
