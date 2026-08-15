#!/bin/sh
# Assemble a tenzro-node package from an already-built binary.
#
# The binary takes the better part of an hour to compile — it links llama.cpp
# and aws-lc — and it is built once, in the cloud, on a machine chosen so the
# result runs everywhere the fleet does. Rebuilding it locally to produce a
# package would mean the packaged artifact is not the one that was tested.
#
# So this does the other half: takes the artifact, adds the unit, the account
# and the configuration template, and produces something dpkg can install. It
# needs no toolchain and takes a second, which is the point — the slow step
# happens once and every package after that is assembly.
#
# Usage:
#   ./deploy/package-from-binary.sh path/to/tenzro-node path/to/tenzro [version]
set -eu

BIN="${1:?usage: $0 <tenzro-node binary> [tenzro cli binary] [version]}"
CLI="${2:-}"
VERSION="${3:-$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)}"
ARCH="${ARCH:-amd64}"
OUT="tenzro-node_${VERSION}-1_${ARCH}.deb"

[ -f "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

# A binary that will not run on the target is worse than no package, and the
# failure surfaces at first boot on a machine nobody can reach yet.
if command -v objdump >/dev/null 2>&1; then
  need=$(objdump -T "$BIN" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1)
  echo "built against $need"
fi

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

install -D -m755 "$BIN"                          "$root/usr/bin/tenzro-node"
# The operator's command line, in the same package as the daemon. A node
# somebody has to reach for a second package to interrogate is a node they will
# interrogate less.
[ -n "$CLI" ] && [ -f "$CLI" ] && install -D -m755 "$CLI" "$root/usr/bin/tenzro"
install -D -m644 deploy/systemd/tenzro-node.service "$root/usr/lib/systemd/system/tenzro-node.service"
install -D -m644 deploy/sysusers/tenzro.conf     "$root/usr/lib/sysusers.d/tenzro.conf"
install -D -m644 deploy/config/node.env          "$root/usr/share/tenzro/node.env"

size=$(du -ks "$root" | cut -f1)
mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: tenzro-node
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6, ca-certificates, systemd
Installed-Size: ${size}
Maintainer: Tenzro <eng@tenzro.com>
Homepage: https://github.com/tenzro/tenzro-network
Description: Tenzro network node
 A full node on the Tenzro network: validator, and optionally a provider of
 compute, storage or database capacity.
 .
 Runs as a system account with its identity and wallets under /var/lib/tenzro.
 Those are the machine's participation in the chain and no reinstall
 regenerates them, so they are state an upgrade never touches.
 .
 Includes the `tenzro` command line, so a machine that runs a node can be
 asked about it without installing anything else.
 .
 Installs configured for nothing in particular and starts anyway: a node with
 no boot peers is alone rather than broken, and says so.
EOF

# Seeds /etc/tenzro/node.env once and never again. Not a conffile: an upgrade
# should not even be able to offer to replace an operator's boot nodes, and
# dpkg's three-way prompt on a machine nobody is watching is a machine that
# stops booting cleanly.
cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if [ ! -e /etc/tenzro/node.env ]; then
        mkdir -p /etc/tenzro
        cp /usr/share/tenzro/node.env /etc/tenzro/node.env
        chmod 0644 /etc/tenzro/node.env
    fi
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers /usr/lib/sysusers.d/tenzro.conf || true
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
    fi
fi
exit 0
EOF
chmod 755 "$root/DEBIAN/postinst"

# Removal leaves /var/lib/tenzro alone. Purging a node's identity because
# somebody removed a package is the one thing this must never do on its own.
cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    echo "tenzro-node: /var/lib/tenzro has been left in place."
    echo "  It holds this machine's identity and wallets, which nothing can"
    echo "  regenerate. Remove it deliberately if that is what you want."
fi
exit 0
EOF
chmod 755 "$root/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$root" "$OUT" >/dev/null
echo "built $OUT"
dpkg-deb -c "$OUT" | awk '{print "  " $6}' | grep -v '/$'
