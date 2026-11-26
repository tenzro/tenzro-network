#!/usr/bin/env bash
# Tenzro's own package sources: an apt repository and a dnf repository over a release's .deb and
# .rpm packages (the node's and Tenzro Control's), laid out to be served from downloads.tenzro.com.
#
#   make-repos.sh <packages-dir> <out-dir>
#
# Writes <out-dir>/apt (pool/ and dists/stable/main/binary-<arch>/), <out-dir>/rpm (the packages
# and repodata/), and the files a machine installs to use them: tenzro.list and tenzro.repo.
#
# apt and dnf trust a repository only through an OpenPGP signature. The release key is not an
# OpenPGP key, so signing waits for one: set TENZRO_REPO_KEY to the signer's OpenPGP key (its
# fingerprint, in the signer's gpg keyring; GNUPGHOME names that keyring when it is not ~/.gnupg)
# and the repositories and the .rpm packages are signed and the public key is written as
# tenzro-repo.asc. Without it the trees are built for checking
# and marked UNSIGNED, and this script exits 3 so nothing publishes them by mistake.
set -euo pipefail
pkgs=$(cd "${1:?usage: make-repos.sh <packages-dir> <out-dir>}" && pwd)
out=${2:?usage: make-repos.sh <packages-dir> <out-dir>}
BASE=${TENZRO_REPO_URL:-https://downloads.tenzro.com}
KEY=${TENZRO_REPO_KEY:-}
need() { for tool; do command -v "$tool" >/dev/null || { echo "REFUSING: $tool not found" >&2; exit 1; }; done; }
shopt -s nullglob
debs=("$pkgs"/tenzro-*.deb)
rpms=("$pkgs"/tenzro-*.rpm)
[ ${#debs[@]} -gt 0 ] || [ ${#rpms[@]} -gt 0 ] || { echo "REFUSING: no tenzro .deb or .rpm in $pkgs" >&2; exit 1; }
[ ${#debs[@]} -eq 0 ] || need dpkg-deb dpkg-scanpackages gzip sha256sum
[ ${#rpms[@]} -eq 0 ] || need createrepo_c
[ -z "$KEY" ] || need gpg
[ -z "$KEY" ] || [ ${#rpms[@]} -eq 0 ] || need rpmsign
rm -rf "$out/apt" "$out/rpm"
mkdir -p "$out/apt/pool/main" "$out/rpm"

# apt: one suite, one component, a Packages index per architecture.
if [ ${#debs[@]} -gt 0 ]; then
    cp "${debs[@]}" "$out/apt/pool/main/"
    (
        cd "$out/apt"
        archs=$(for d in pool/main/*.deb; do dpkg-deb -f "$d" Architecture; done | sort -u)
        for a in $archs; do
            dir=dists/stable/main/binary-$a
            mkdir -p "$dir"
            dpkg-scanpackages --arch "$a" --multiversion pool /dev/null > "$dir/Packages"
            gzip -9nk "$dir/Packages"
        done
        cd dists/stable
        {
            echo "Origin: Tenzro"
            echo "Label: Tenzro"
            echo "Suite: stable"
            echo "Codename: stable"
            echo "Date: $(LC_ALL=C date -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}" '+%a, %d %b %Y %H:%M:%S UTC')"
            echo "Architectures: $(echo $archs)"
            echo "Components: main"
            echo "SHA256:"
            for f in main/binary-*/Packages main/binary-*/Packages.gz; do
                printf ' %s %s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$(wc -c < "$f" | tr -d ' ')" "$f"
            done
        } > Release
    )
fi

# dnf: the packages and their repodata.
if [ ${#rpms[@]} -gt 0 ]; then
    cp "${rpms[@]}" "$out/rpm/"
    [ -z "$KEY" ] || rpmsign --define "_gpg_name $KEY" --define "_gpg_path ${GNUPGHOME:-$HOME/.gnupg}" --addsign "$out"/rpm/*.rpm
    createrepo_c --quiet "$out/rpm"
fi

cat > "$out/tenzro.list" <<EOF
deb [signed-by=/usr/share/keyrings/tenzro.gpg] $BASE/apt stable main
EOF
cat > "$out/tenzro.repo" <<EOF
[tenzro]
name=Tenzro
baseurl=$BASE/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$BASE/tenzro-repo.asc
EOF

if [ -z "$KEY" ]; then
    echo "The repositories are not signed: no OpenPGP key is set (TENZRO_REPO_KEY)." > "$out/UNSIGNED"
    echo "UNSIGNED: $out holds repositories for checking only; set TENZRO_REPO_KEY to sign them" >&2
    exit 3
fi
rm -f "$out/UNSIGNED"
gpg --batch --yes --armor --export "$KEY" > "$out/tenzro-repo.asc"
if [ -f "$out/apt/dists/stable/Release" ]; then
    gpg --batch --yes --local-user "$KEY" --clearsign -o "$out/apt/dists/stable/InRelease" "$out/apt/dists/stable/Release"
    gpg --batch --yes --local-user "$KEY" --armor --detach-sign -o "$out/apt/dists/stable/Release.gpg" "$out/apt/dists/stable/Release"
fi
if [ -f "$out/rpm/repodata/repomd.xml" ]; then
    gpg --batch --yes --local-user "$KEY" --armor --detach-sign -o "$out/rpm/repodata/repomd.xml.asc" "$out/rpm/repodata/repomd.xml"
fi
echo "SIGNED: $out"
