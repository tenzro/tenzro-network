#!/usr/bin/env bash
# Runs INSIDE a clean container (root). Installs the package, checks it, removes,
# reinstalls and upgrades. Driven by run-container-tests.sh.
#
# Environment:
#   PKG_NAME       package name (tenzro-cpu / tenzro-cuda)
#   PKG_FILE       /pkgs/<file> to install
#   PKG_FILE_NEXT  /pkgs/<file> of a later revision, for the upgrade step (optional)
#   OTHER_FILE     the other flavour's package, for the conflict step (optional)
#   EXPECT_NODE_SHA, EXPECT_CLI_SHA   sha256 of the binaries in the release archive
#   EXPECT_REFUSED=1   the distribution is too old: the install must be refused, cleanly
#   EXPECT_GATE    READY or "NOT READY": what tenzro-check must say here
set -uo pipefail
fails=0
ok() { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }

if command -v apt-get >/dev/null; then
    pm=apt; export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    install() { apt-get install -y "$@"; }
    remove() { apt-get remove -y "$@"; }
    purge() { apt-get purge -y "$@"; }
    installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed'; }
else
    pm=dnf
    install() { dnf install -y "$@"; }
    remove() { dnf remove -y "$@"; }
    purge() { dnf remove -y "$@"; }
    installed() { rpm -q "$1" >/dev/null 2>&1; }
fi
. /etc/os-release; echo "== $PRETTY_NAME, $pm, glibc $(ldd --version | head -1 | awk '{print $NF}'), $(uname -m)"
log=/tmp/install.log

if [ "${EXPECT_REFUSED:-}" = 1 ]; then
    if install "$PKG_FILE" >"$log" 2>&1; then bad "install was accepted on a system that is too old"; else ok "install refused on this old system"; fi
    sed -n '1,200p' "$log" | grep -iE "libc6|GLIBC|unmet|nothing provides|requires|conflict|depends" | head -5 | sed 's/^/  | /'
    installed "$PKG_NAME" && bad "package left half-installed" || ok "nothing left installed"
    [ ! -e /usr/lib/tenzro ] && ok "no files left" || bad "files left behind"
    [ $fails = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL ($fails)"; exit $fails
fi

echo "-- install"
if install "$PKG_FILE" >"$log" 2>&1; then ok "install"; else bad "install"; tail -20 "$log"; fi
echo "---- install output (the user sees this) ----"; sed -n '/^Tenzro is installed\|^$/,$p' "$log" | sed -n '/Tenzro is installed/,/Remove everything/p'; echo "---------------------------------------------"
check "postinst printed the gate result" grep -q "Tenzro hardware check" "$log"
check "postinst said nothing was started" grep -q "Nothing was started" "$log"
case "${EXPECT_GATE:-}" in
    READY) check "gate says READY" grep -qE "^(>>> )?READY:" "$log" ;;
    "NOT READY") check "gate says NOT READY with a reason" grep -qE "^(>>> )?NOT READY:" "$log" ;;
esac

verify_installed() {
    check "tenzro on PATH" command -v tenzro
    check "tenzro-node on PATH" command -v tenzro-node
    v=$(tenzro --version 2>&1); echo "  tenzro --version: $v"
    echo "$v" | grep -q '^tenzro [0-9]' && ok "tenzro --version" || bad "tenzro --version"
    v=$(tenzro-node --version 2>&1); echo "  tenzro-node --version: $v"
    echo "$v" | grep -q '^tenzro-node [0-9]' && ok "tenzro-node --version" || bad "tenzro-node --version"
    tenzro setup --help 2>&1 | grep -q 'Guided setup' && ok "tenzro setup --help" || bad "tenzro setup --help"
    [ "$(sha256sum /usr/lib/tenzro/bin/tenzro-node | cut -d' ' -f1)" = "$EXPECT_NODE_SHA" ] && ok "tenzro-node bytes equal the release archive's" || bad "tenzro-node bytes differ"
    [ "$(sha256sum /usr/lib/tenzro/bin/tenzro | cut -d' ' -f1)" = "$EXPECT_CLI_SHA" ] && ok "tenzro bytes equal the release archive's" || bad "tenzro bytes differ"
    if ldd /usr/lib/tenzro/bin/tenzro-node 2>&1 | grep -q 'not found'; then
        echo "  ldd: $(ldd /usr/lib/tenzro/bin/tenzro-node 2>&1 | grep 'not found' | tr -s ' \t' ' ' | tr '\n' ';')"
        if [ "${EXPECT_MISSING_CUDA:-}" = 1 ]; then ok "ldd: only the NVIDIA runtime libraries are missing (expected without CUDA)"; else bad "ldd: libraries not found"; fi
    else ok "ldd: every library resolves"; fi
    if [ -d /usr/lib/tenzro/lib ]; then
        r=$(ldd /usr/lib/tenzro/bin/tenzro-node 2>&1 | awk '/libonnxruntime\.so/ {print $3}')
        case "$r" in /usr/lib/tenzro/lib/*) ok "ONNX Runtime resolves through \$ORIGIN/../lib to $r" ;; *) bad "ONNX Runtime resolves to '$r'" ;; esac
    fi
    out=$(tenzro-check 2>&1); rc=$?
    echo "$out" | grep -q "Next step" && ok "tenzro-check runs (exit $rc) and names the next step" || bad "tenzro-check"
    check "no systemd unit installed" bash -c '! ls /etc/systemd/system /usr/lib/systemd/system 2>/dev/null | grep -qi tenzro'
    check "no tenzro process running" bash -c '! pgrep -x tenzro-node'
    check "no data directory created" bash -c '! ls -d /root/.tenzro /var/lib/tenzro 2>/dev/null | grep -q .'
}
verify_installed

echo "-- remove"
remove "$PKG_NAME" >"$log" 2>&1 && ok "remove" || { bad "remove"; tail -5 "$log"; }
grep -h "programs were removed" "$log" | head -1 | sed 's/^/  user sees: /'
installed "$PKG_NAME" && bad "still installed" || ok "package gone"
check "/usr/lib/tenzro removed" test ! -e /usr/lib/tenzro
check "/usr/bin/tenzro removed" test ! -e /usr/bin/tenzro
check "/usr/bin/tenzro-node removed" test ! -e /usr/bin/tenzro-node
check "docs removed" test ! -e /usr/share/doc/$PKG_NAME

echo "-- reinstall"
install "$PKG_FILE" >"$log" 2>&1 && ok "reinstall" || { bad "reinstall"; tail -5 "$log"; }
verify_installed

if [ -n "${PKG_FILE_NEXT:-}" ]; then
    echo "-- upgrade"
    install "$PKG_FILE_NEXT" >"$log" 2>&1 && ok "upgrade" || { bad "upgrade"; tail -10 "$log"; }
    grep -q "^version=.*-2$" /usr/lib/tenzro/PACKAGE-INFO && ok "PACKAGE-INFO shows the new revision" || bad "PACKAGE-INFO not updated"
    grep -h "was upgraded" "$log" | head -1 | sed 's/^/  user sees: /'
    check "upgrade message printed" grep -q "was upgraded" "$log"
    if [ "$pm" = apt ]; then check "one package installed" bash -c "[ \$(dpkg -l | grep -c '^ii  $PKG_NAME') = 1 ]"; else check "one package installed" bash -c "[ \$(rpm -q $PKG_NAME | wc -l) = 1 ]"; fi
    verify_installed
fi

if [ -n "${OTHER_FILE:-}" ]; then
    echo "-- conflict with the other flavour"
    install "$OTHER_FILE" >"$log" 2>&1; rc=$?
    echo "  exit $rc; $(grep -iE 'conflict|Removing|Remov' "$log" | head -3 | tr '\n' '|')"
    if [ "$pm" = apt ]; then
        # apt replaces the package (Conflicts + Replaces).
        installed "$PKG_NAME" && bad "$PKG_NAME is still installed beside the other flavour" || ok "$PKG_NAME was replaced"
        [ $rc = 0 ] && ok "install of the other flavour succeeded by replacing" || bad "install of the other flavour failed"
    else
        # dnf refuses and the user is told to swap.
        [ $rc != 0 ] && ok "dnf refuses to install both" || bad "both installed"
        if dnf swap -y "$PKG_NAME" "$(rpm -qp --qf '%{NAME}' "$OTHER_FILE")" --allowerasing "$OTHER_FILE" >"$log" 2>&1 || dnf install -y --allowerasing "$OTHER_FILE" >"$log" 2>&1; then
            ok "dnf swap/--allowerasing replaces it"
        else bad "swap failed"; tail -5 "$log"; fi
    fi
    [ "$(grep '^flavour=' /usr/lib/tenzro/PACKAGE-INFO | cut -d= -f2)" != "$(echo $PKG_NAME | sed s/tenzro-//)" ] && ok "other flavour is now the installed one" || bad "flavour unchanged"
fi
[ $fails = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL ($fails)"
exit $fails
