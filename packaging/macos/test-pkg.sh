#!/bin/bash
# Install the package on a disposable macOS machine (a CI runner), check it, remove it.
# NEVER run this on a machine you use: it installs into /usr/local and /Applications.
#   test-pkg.sh <tenzro-VERSION-macos.pkg>
set -uo pipefail
pkg=${1:?usage: test-pkg.sh <package.pkg>}
fails=0
ok() { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { local w=$1; shift; if "$@" >/dev/null 2>&1; then ok "$w"; else bad "$w"; fi; }

echo "== $(sw_vers -productName) $(sw_vers -productVersion), $(uname -m)"
echo "-- install"
if sudo installer -verbose -pkg "$pkg" -target / >/tmp/tz-installer.log 2>&1; then ok "installer exit 0"; else bad "installer"; cat /tmp/tz-installer.log; fi
echo "---- installer output (log) ----"; grep -v '^$' /tmp/tz-installer.log | tail -40; echo "--------------------------------"
check "tenzro on PATH" command -v tenzro
v=$(tenzro --version 2>&1); echo "  tenzro --version: $v"; echo "$v" | grep -q '^tenzro [0-9]' && ok "tenzro --version" || bad "tenzro --version"
v=$(tenzro-node --version 2>&1); echo "  tenzro-node --version: $v"; echo "$v" | grep -q '^tenzro-node [0-9]' && ok "tenzro-node --version" || bad "tenzro-node --version"
tenzro setup --help 2>&1 | grep -q 'Guided setup' && ok "tenzro setup --help" || bad "tenzro setup --help"
info=/usr/local/lib/tenzro/PACKAGE-INFO
cat "$info"
want=$(grep '^flavour=' "$info" | cut -d= -f2)
case "$(uname -m)" in arm64) [ "$want" = metal ] && ok "Apple silicon got the Metal build" || bad "wrong flavour $want" ;; *) [ "$want" = cpu ] && ok "Intel got the CPU build" || bad "wrong flavour $want" ;; esac
src=$(grep '^source_archive_sha256=' "$info" | cut -d= -f2)
echo "  source archive sha256: $src"
out=$(tenzro-check 2>&1); rc=$?; echo "$out" | sed 's/^/  | /'
echo "$out" | grep -q "Next step" && ok "tenzro-check runs (exit $rc)" || bad "tenzro-check"
check "launcher app present" test -x /Applications/Tenzro.app/Contents/MacOS/Tenzro
check "no launchd job added" bash -c '! launchctl list | grep -qi tenzro'
check "no tenzro process running" bash -c '! pgrep -x tenzro-node'
check "no tenzro daemon plist" bash -c '! ls /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null | grep -qi tenzro'
echo "-- receipts"; pkgutil --pkgs | grep tenzro

echo "-- uninstall"
sudo tenzro-uninstall && ok "tenzro-uninstall" || bad "tenzro-uninstall"
check "/usr/local/lib/tenzro gone" test ! -e /usr/local/lib/tenzro
check "/usr/local/bin/tenzro gone" test ! -e /usr/local/bin/tenzro
check "launcher gone" test ! -e /Applications/Tenzro.app
check "receipts forgotten" bash -c '! pkgutil --pkgs | grep -q tenzro'
echo "-- reinstall"
sudo installer -pkg "$pkg" -target / >/dev/null 2>&1 && tenzro --version >/dev/null 2>&1 && ok "reinstall works" || bad "reinstall"
sudo tenzro-uninstall >/dev/null 2>&1
[ $fails = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL ($fails)"
exit $fails
