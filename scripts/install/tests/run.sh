#!/bin/bash
# Tests for scripts/install/install.sh. Needs podman (or docker) and a SITE dir:
# a copy of the release files (SHA256SUMS, SHA256SUMS.sig, matrix.json and at least
# tenzro-node-linux-x86_64-cpu.tar.gz; add tenzro-node-macos-x86_64-cpu.tar.gz for the
# wrong-architecture case). Runs every case in a throwaway container as a normal
# user, against file:// (no network), and prints PASS or FAIL per case.
#
#   scripts/install/tests/run.sh SITE_DIR [IMAGE ...]      default images: ubuntu:24.04 debian:12 fedora:42
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SITE=$(cd "${1:?usage: run.sh SITE_DIR [IMAGE ...]}" && pwd); shift
IMAGES=("$@"); [ ${#IMAGES[@]} -gt 0 ] || IMAGES=(docker.io/library/ubuntu:24.04 docker.io/library/debian:12 docker.io/library/fedora:42)
CT=$(command -v podman || command -v docker)
INSTALL=$(cd "$HERE/.." && pwd)/install.sh
ARCH=tenzro-node-linux-x86_64-cpu.tar.gz
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0

# tampered copies of the site
mkdir -p "$W/arch" "$W/sig" "$W/sums" "$W/trunc"
for d in arch sig sums trunc; do for f in SHA256SUMS SHA256SUMS.sig matrix.json "$ARCH"; do cp "$SITE/$f" "$W/$d/$f"; done; done
printf 'X' | dd of="$W/arch/$ARCH" bs=1 seek=5000000 conv=notrunc 2>/dev/null          # one byte flipped
head -c 60000000 "$SITE/$ARCH" > "$W/trunc/$ARCH"                                         # truncated download
printf 'AAAA' | dd of="$W/sig/SHA256SUMS.sig" bs=1 seek=20 conv=notrunc 2>/dev/null      # signature altered
sed -i.bak 's/^5d1d0a00/6d1d0a00/' "$W/sums/SHA256SUMS" && rm -f "$W/sums/SHA256SUMS.bak"  # list altered, signature untouched

# prep: a container image per distro with the tools the installer needs
prep() { # prep IMAGE TAG PKGCMD
    printf 'FROM %s\nRUN %s\nRUN useradd -m u 2>/dev/null || adduser -D u\n' "$1" "$3" | $CT build -q -t "$2" - >/dev/null
}
# run IMAGE SITEDIR SCRIPT -> output in $OUT, status in $RC
run() {
    local u=(--user u); [ "${BARE:-}" = 1 ] && u=()
    OUT=$($CT run --rm --network none --memory 4g --cpus 2 "${u[@]}" -e HOME=/home/u -e TERM=dumb \
        -v "$2":/site:ro,Z -v "$INSTALL":/install.sh:ro,Z "$1" sh -c "$3" 2>&1); RC=$?
}
check() { # check NAME EXPECT_RC REGEX [REGEX...]
    local name=$1 want=$2; shift 2; local ok=1
    [ "$RC" = "$want" ] || ok=0
    for re in "$@"; do echo "$OUT" | grep -Eq -- "$re" || ok=0; done
    if [ $ok = 1 ]; then pass=$((pass+1)); echo "PASS  $name"; else failn=$((failn+1)); echo "FAIL  $name (rc=$RC, want $want)"; echo "$OUT" | sed 's/^/        /' | head -25; fi
}
I='sh /install.sh --no-modify-path --base-url file:///site'

# ---- syntax under strict POSIX shells (no containers needed)
for shx in dash "busybox sh"; do
    command -v ${shx%% *} >/dev/null || continue
    if $shx -n "$INSTALL" 2>/dev/null; then pass=$((pass+1)); echo "PASS  syntax ($shx -n)"; else failn=$((failn+1)); echo "FAIL  syntax ($shx -n)"; fi
done

for img in "${IMAGES[@]}"; do
    tag="tenzro-inst-$(echo "$img" | tr '/:.' '---')"
    case "$img" in
        *fedora*) PK='dnf -q -y install openssl file binutils findutils diffutils tar gzip >/dev/null 2>&1' ;;
        *) PK='apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y curl openssl file binutils ca-certificates >/dev/null 2>&1' ;;
    esac
    prep "$img" "$tag" "$PK" || { echo "SKIP  $img (image prep failed, needs network)"; continue; }
    echo "== $img"
    case "$img" in
        *ubuntu*|*fedora*)
            # the links are in ~/.local/bin, which is not on PATH in a container: use the full path
            run "$tag" "$SITE" "$I; echo rc=\$?; echo ---; \$HOME/.local/bin/tenzro --version; \$HOME/.local/bin/tenzro-node --version; ls -l \$HOME/.local/bin"
            check "$img happy path" 0 'rc=0' 'signature +verified' 'checksum +verified' 'self-check +build CPU' 'gate +accepted' 'tenzro 0\.2\.0' 'tenzro-node 0\.2\.0' 'is installed' 'export PATH=.*&& tenzro'
            run "$tag" "$SITE" "$I >/dev/null; $I; echo rc=\$?; ls \$HOME/.tenzro/install/versions | wc -l"
            check "$img second run is an update no-op" 0 'already installed, nothing to download' 'rc=0' 'is installed' '^1$'
            run "$tag" "$SITE" "$I >/dev/null; sh /install.sh --uninstall; ls -A \$HOME/.local/bin \$HOME/.tenzro 2>&1; true"
            check "$img uninstall" 0 'removed' 'No such file|^$' ;;
    esac
    case "$img" in *ubuntu*)
        run "$tag" "$W/arch" "$I; echo rc=\$?; ls -A \$HOME/.tenzro/install/versions \$HOME/.local/bin 2>&1; true"
        check "tampered archive is refused" 0 'rc=1' 'archive does not match the signed list' 'Nothing was installed' 'No such file'
        run "$tag" "$W/trunc" "$I"
        check "truncated archive is refused" 1 'archive does not match the signed list'
        run "$tag" "$W/sig" "$I"
        check "tampered signature is refused" 1 'signature on SHA256SUMS does not verify|not a valid signature'
        run "$tag" "$W/sums" "$I"
        check "altered hash list is refused" 1 'signature on SHA256SUMS does not verify'
        run "$tag" "$SITE" "sh /install.sh --no-modify-path --base-url http://127.0.0.1:9"
        check "unreachable site gives a clear error" 1 'could not download' 'fix:' '--from'
        run "$tag" "$SITE" "sh /install.sh --no-modify-path --from /site --base-url http://127.0.0.1:9"
        check "offline --from works" 0 'signature +verified' 'is installed'
        run "$tag" "$SITE" "$I --dry-run; ls -A \$HOME/.tenzro 2>&1; true"
        check "dry run changes nothing" 0 'Dry run' 'No such file'
        run "$tag" "$SITE" "printf 'export A=1\\n' > \$HOME/.profile; sh /install.sh --modify-path --base-url file:///site >/dev/null; cat \$HOME/.profile; sh /install.sh --uninstall >/dev/null; echo ---; cat \$HOME/.profile"
        check "--modify-path adds a marked block and uninstall removes only it" 0 '>>> tenzro >>>' 'export PATH=.*/.local/bin' '---' '^export A=1$'
        [ "$(echo "$OUT" | sed -n '/^---$/,$p' | grep -c tenzro)" = 0 ] && { pass=$((pass+1)); echo "PASS  uninstall leaves the profile as it was"; } || { failn=$((failn+1)); echo "FAIL  profile still mentions tenzro after uninstall"; }
        run "$tag" "$SITE" "$I --version 9.9.9"
        check "wrong --version is refused" 1 'you asked for 9.9.9'
        run "$tag" "$SITE" "$I --target tenzro-node-nonexistent"
        check "unknown --target is refused" 1 'is not in this release'
        run "$tag" "$SITE" "NO_COLOR=1 $I --dry-run | cat -v | grep -c '\\^\\['"
        check "NO_COLOR/pipe prints no escape codes" 1 '^0$'
        run "$tag" "$SITE" "mkdir -p \$HOME/.local/bin && echo x > \$HOME/.local/bin/tenzro; $I"
        check "does not overwrite a foreign tenzro" 1 'already exists and is not a link'
        if [ -f "$SITE/tenzro-node-macos-x86_64-cpu.tar.gz" ]; then
            run "$tag" "$SITE" "$I --target tenzro-node-macos-x86_64-cpu"
            check "wrong platform build is refused" 1 'this build is not for this system|does not run on this machine' 'Nothing was installed'
        fi
        # bare image: no openssl -> fail closed
        BARE=1 run "$img" "$SITE" "mkdir -p /home/u; sh /install.sh --base-url file:///site"
        [ "$RC" = 1 ] && echo "$OUT" | grep -q 'openssl was not found' && { pass=$((pass+1)); echo "PASS  no openssl: fails closed"; } || { failn=$((failn+1)); echo "FAIL  no openssl (rc=$RC)"; echo "$OUT" | head; } ;;
    esac
    case "$img" in *debian*)
        run "$tag" "$SITE" "$I"
        check "old glibc (Debian 12) is refused before download, with a fix" 1 'glibc is too old' 'needs glibc 2\.39' 'fix:' ;;
    esac
done
echo; echo "passed $pass, failed $failn"
[ $failn = 0 ]
