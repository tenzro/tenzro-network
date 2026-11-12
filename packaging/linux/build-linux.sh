#!/usr/bin/env bash
# Build the .deb and .rpm of one Linux release archive, repackaging the exact bytes.
#
#   build-linux.sh <tenzro-node-linux-ARCH-FLAVOUR.tar.gz> <out-dir>
#
# FLAVOUR is cpu or cuda. The packages are tenzro-cpu and tenzro-cuda; they
# conflict with and replace each other and both provide `tenzro`.
# Layout (the binaries' $ORIGIN/../lib run path is kept):
#   /usr/lib/tenzro/bin/{tenzro,tenzro-node,tenzro-check}
#   /usr/lib/tenzro/lib/libonnxruntime*      (CUDA builds)
#   /usr/lib/tenzro/share/network/<chain_id>.toml  the network profile the node joins through
#   /usr/lib/tenzro/PACKAGE-INFO             (version, source archive sha256, commits)
#   /usr/bin/{tenzro,tenzro-node,tenzro-check}  symlinks into /usr/lib/tenzro/bin
#   /usr/bin/tenzro-node-install             the archive's own installer, unchanged
#   /usr/share/doc/<package>/                licence, notice, first-run text
#
# Environment:
#   TENZRO_VERSION   default: the version of the node in the repository
#   PKG_REVISION     package revision, default 1
#   PUBLIC_COMMIT    default: the commit named by provenance-*.intoto.json beside the archive
#   DEB_ONLY / RPM_ONLY   build one kind
#   RPM_IMAGE        container image that has rpmbuild (default: built from fedora, see build-rpm-image.sh)
#   CONTAINER        podman or docker (default: whichever exists)
set -euo pipefail

archive=${1:?usage: build-linux.sh <archive.tar.gz> <out-dir>}
out=${2:?usage: build-linux.sh <archive.tar.gz> <out-dir>}
here=$(cd "$(dirname "$0")" && pwd)
pk=$(cd "$here/.." && pwd)
repo=$(cd "$pk/.." && pwd)
archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")
mkdir -p "$out"; out=$(cd "$out" && pwd)
dist=$(dirname "$archive")

name=$(basename "$archive" .tar.gz)
case "$name" in
    tenzro-node-linux-x86_64-cpu|tenzro-node-linux-x86_64-cuda|tenzro-node-linux-aarch64-cpu|tenzro-node-linux-aarch64-cuda) ;;
    *) echo "REFUSING: $name is not a Linux cpu or cuda archive" >&2; exit 64 ;;
esac
arch=$(echo "$name" | cut -d- -f4); flavour=$(echo "$name" | cut -d- -f5)
case "$arch" in
    x86_64) deb_arch=amd64; rpm_arch=x86_64 ;;
    aarch64) deb_arch=arm64; rpm_arch=aarch64 ;;
esac
pkg=tenzro-$flavour
other=tenzro-$([ "$flavour" = cpu ] && echo cuda || echo cpu)
version=${TENZRO_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/tenzro-node/Cargo.toml" | head -1)}
[ -n "$version" ] || { echo "REFUSING: no version" >&2; exit 1; }
rev=${PKG_REVISION:-1}

src_sha=$(sha256sum "$archive" | cut -d' ' -f1)
if [ -f "$dist/SHA256SUMS" ]; then
    listed=$(awk -v f="$(basename "$archive")" '$2==f {print $1}' "$dist/SHA256SUMS")
    [ -z "$listed" ] || [ "$listed" = "$src_sha" ] || { echo "REFUSING: $archive does not match $dist/SHA256SUMS" >&2; exit 1; }
fi
release_commit=$(jq -r .commit "$dist/$name.buildenv.json" 2>/dev/null || echo unknown)
public_commit=${PUBLIC_COMMIT:-$(jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit // empty' "$dist"/provenance-*.intoto.json 2>/dev/null | head -1)}
public_commit=${public_commit:-unknown}
packaging_commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)

work=$(mktemp -d "${TMPDIR:-/tmp}/tzpkg-$name.XXXXXX")
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
src=$work/$name
[ -f "$src/bin/tenzro" ] && [ -f "$src/bin/tenzro-node" ] || { echo "REFUSING: $archive lacks bin/tenzro and bin/tenzro-node" >&2; exit 1; }

# Every file carries the release commit time the archive was packed with, so a rebuild gives the same bytes.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(stat -c %Y "$src/bin/tenzro")}

# Minimum system libraries, from the binaries' own symbol versions.
need() { # prefix -> highest version among all ELF files
    local f v best=""
    for f in "$src"/bin/* "$src"/lib/*.so*; do
        [ -f "$f" ] || continue
        v=$(readelf -V "$f" 2>/dev/null | grep -o "$1[0-9.]*" | sed "s/^$1//" | sort -uV | tail -1) || true
        [ -n "$v" ] && best=$(printf '%s\n%s\n' "$best" "$v" | sed '/^$/d' | sort -V | tail -1)
    done
    echo "$best"
}
glibc=$(need GLIBC_); glibcxx=$(need GLIBCXX_)
gcc_for() { case "$1" in 3.4.2[0-8]) echo 10.1 ;; 3.4.29) echo 11.1 ;; 3.4.30) echo 12.1 ;; 3.4.31) echo 13.1 ;; 3.4.32) echo 13.2 ;; 3.4.33) echo 14.1 ;; 3.4.34) echo 15.1 ;; "") echo "" ;; *) echo "unknown GLIBCXX $1" >&2; return 1 ;; esac; }
gcc_min=$(gcc_for "$glibcxx")
cuda_rt=""
if [ -e "$src/lib/libonnxruntime_providers_cuda.so" ]; then
    cuda_rt=$(readelf -d "$src/lib/libonnxruntime_providers_cuda.so" | sed -n 's/.*\[libcudart\.so\.\([0-9]*\)\].*/\1/p' | head -1)
fi
echo "$name: glibc >= ${glibc:-none}, libstdc++ >= ${gcc_min:-none} (GLIBCXX_$glibcxx), cuda runtime ${cuda_rt:-none}"
[ "$flavour" = cuda ] && [ -z "$cuda_rt" ] && { echo "REFUSING: a cuda archive without the CUDA provider" >&2; exit 1; }
[ "$flavour" = cpu ] && [ -n "$cuda_rt" ] && { echo "REFUSING: a cpu archive carrying the CUDA provider" >&2; exit 1; }

# The file tree both package kinds install.
root=$work/root
install -d "$root/usr/lib/tenzro/bin" "$root/usr/bin" "$root/usr/share/doc/$pkg"
install -m755 "$src/bin/tenzro" "$src/bin/tenzro-node" "$root/usr/lib/tenzro/bin/"
if [ -d "$src/lib" ]; then cp -a "$src/lib" "$root/usr/lib/tenzro/lib"; fi
# The network profile, found by the node at <bin dir>/../share/network.
if [ -d "$src/share" ]; then cp -a "$src/share" "$root/usr/lib/tenzro/share"; fi
install -m755 "$pk/common/tenzro-check" "$root/usr/lib/tenzro/bin/tenzro-check"
install -m755 "$src/tenzro-node-install" "$root/usr/bin/tenzro-node-install"
for b in tenzro tenzro-node tenzro-check; do ln -s "../lib/tenzro/bin/$b" "$root/usr/bin/$b"; done
cat > "$root/usr/lib/tenzro/PACKAGE-INFO" <<EOF
package=$pkg
version=$version-$rev
flavour=$flavour
architecture=$arch
cuda_runtime=$cuda_rt
source_archive=$(basename "$archive")
source_archive_sha256=$src_sha
release_commit=$release_commit
public_source_commit=$public_commit
packaging_commit=$packaging_commit
EOF
chmod 644 "$root/usr/lib/tenzro/PACKAGE-INFO"
install -m644 "$repo/LICENSE" "$root/usr/share/doc/$pkg/LICENSE"
install -m644 "$repo/NOTICE" "$root/usr/share/doc/$pkg/NOTICE"
install -m644 "$pk/common/FIRST-RUN.txt" "$root/usr/share/doc/$pkg/FIRST-RUN.txt"
if [ -d "$src/lib" ]; then cat "$pk/linux/copyright.in"; else sed '/^Files: usr\/lib\/tenzro\/lib/,$d' "$pk/linux/copyright.in"; fi \
    | sed "s/@PKG@/$pkg/g" > "$root/usr/share/doc/$pkg/copyright"
chmod 644 "$root/usr/share/doc/$pkg/copyright"
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

summary="Tenzro Network: node, command line and hardware check ($flavour build)"
case "$flavour" in
  cpu) blurb="This is the CPU build. It runs on any machine and serves models on the CPU." ;;
  cuda) blurb="This is the CUDA build, for machines with an NVIDIA GPU. It needs the NVIDIA driver and the CUDA $cuda_rt runtime libraries with cuDNN 9, which are not part of this package." ;;
esac

build_deb() {
    local d=$work/debroot; mkdir -p "$d"; cp -a "$root/." "$d/"; install -d "$d/DEBIAN"
    {
      echo "Package: $pkg"
      echo "Version: $version-$rev"
      echo "Architecture: $deb_arch"
      echo "Maintainer: Tenzro Network <eng@tenzro.com>"
      echo "Section: net"
      echo "Priority: optional"
      echo "Homepage: https://tenzro.com"
      echo "Depends: libc6 (>= $glibc)${gcc_min:+, libstdc++6 (>= $gcc_min)}, libgcc-s1"
      echo "Provides: tenzro"
      echo "Conflicts: tenzro, $other"
      echo "Replaces: tenzro, $other"
      echo "Description: $summary"
      echo " Installs the tenzro command line and the tenzro-node program, a hardware"
      echo " check (tenzro-check) and the archive's own installer (tenzro-node-install)."
      echo " $blurb"
      echo " ."
      echo " Nothing is started and nothing joins the network when the package is"
      echo " installed. Open a terminal and run: tenzro"
    } > "$d/DEBIAN/control"
    install -m755 "$here/deb/postinst" "$here/deb/postrm" "$d/DEBIAN/"
    local f=$out/${pkg}_$version-${rev}_$deb_arch.deb
    dpkg-deb --root-owner-group -Zzstd -z15 --build "$d" "$f" >/dev/null
    echo "built $f"
}

build_rpm() {
    local ctr=${CONTAINER:-$(command -v podman || command -v docker)}
    local image=${RPM_IMAGE:-tenzro-rpmbuild}
    local specdir=$work/rpm; mkdir -p "$specdir"
    sed "s|@PKG@|$pkg|g; s|@OTHER@|$other|g; s|@VERSION@|$version|g; s|@REV@|$rev|g; s|@ARCH@|$rpm_arch|g; s|@SUMMARY@|$summary|g; s|@BLURB@|$blurb|g; s|@GLIBC@|$glibc|g; s|@GLIBCXX@|$glibcxx|g; s|@EPOCH@|$SOURCE_DATE_EPOCH|g" \
        "$here/rpm/tenzro.spec.in" > "$specdir/tenzro.spec"
    if ! "$ctr" image exists "$image" 2>/dev/null && ! "$ctr" image inspect "$image" >/dev/null 2>&1; then
        "$here/build-rpm-image.sh" "$image"
    fi
    cat > "$specdir/run.sh" <<EOS
set -e
mkdir -p /tmp/rpm
rpmbuild -bb --noclean --target $rpm_arch-linux --define "_topdir /tmp/rpm" --define "_payload /payload" /spec/tenzro.spec > /tmp/rpm.log 2>&1 || { cat /tmp/rpm.log; exit 1; }
cp /tmp/rpm/RPMS/*/*.rpm /out/
EOS
    "$ctr" run --rm -v "$root:/payload:ro" -v "$specdir:/spec:ro" -v "$out:/out" -e SOURCE_DATE_EPOCH "$image" bash /spec/run.sh
    echo "built $out/$pkg-$version-$rev.$rpm_arch.rpm"
}

[ -n "${RPM_ONLY:-}" ] || build_deb
[ -n "${DEB_ONLY:-}" ] || build_rpm
