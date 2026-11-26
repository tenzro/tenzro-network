#!/usr/bin/env bash
# Tenzro's own Android app source: an F-Droid repository over a release's signed Tenzro Control
# APK, served from downloads.tenzro.com/fdroid/repo, so a phone, tablet, TV box or car updates
# the app with no store (any F-Droid client adds it by its address and key fingerprint).
#
#   make-app-source.sh <tenzro-control apk> <out-dir>
#
# Writes <out-dir>/fdroid (config, metadata from apps/tenzro-control/android/fdroid, and repo/
# with the APK and the index). Needs fdroidserver (`fdroid`).
#
# An F-Droid client trusts a repository only through the signature on its index. Set
# TENZRO_FDROID_KEYSTORE to the repository keystore, TENZRO_FDROID_KEY_ALIAS to its key and
# TENZRO_FDROID_KEYSTORE_PASS and TENZRO_FDROID_KEY_PASS to their passwords, and the index is
# signed. Without them the repository is built for checking, marked UNSIGNED, and this script
# exits 3 so nothing publishes it by mistake.
set -euo pipefail
apk=${1:?usage: make-app-source.sh <tenzro-control apk> <out-dir>}
out=${2:?usage: make-app-source.sh <tenzro-control apk> <out-dir>}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
command -v fdroid >/dev/null || { echo "REFUSING: fdroid (fdroidserver) not found" >&2; exit 1; }
[ -f "$apk" ] || { echo "REFUSING: no APK at $apk" >&2; exit 1; }
base=${TENZRO_DOWNLOADS:-https://downloads.tenzro.com}
dir=$out/fdroid
rm -rf "$dir"; mkdir -p "$dir/repo" "$dir/metadata"
cp "$apk" "$dir/repo/"
cp "$repo/apps/tenzro-control/android/fdroid/com.tenzro.control.yml" "$dir/metadata/"
{
    echo "repo_url: ${base%/}/fdroid/repo"
    echo "repo_name: Tenzro"
    echo "repo_description: Tenzro Control for Android phones, tablets, TV boxes and cars, from Tenzro, with no store."
    if [ -n "${TENZRO_FDROID_KEYSTORE:-}" ]; then
        echo "keystore: $TENZRO_FDROID_KEYSTORE"
        echo "repo_keyalias: ${TENZRO_FDROID_KEY_ALIAS:?TENZRO_FDROID_KEY_ALIAS is required with TENZRO_FDROID_KEYSTORE}"
        echo "keystorepass: {env: TENZRO_FDROID_KEYSTORE_PASS}"
        echo "keypass: {env: TENZRO_FDROID_KEY_PASS}"
    fi
} > "$dir/config.yml"
chmod 600 "$dir/config.yml"
# A repository names the categories its apps may use; lint and the index read them here.
mkdir -p "$dir/config"
printf 'System:\n  name: System\n' > "$dir/config/categories.yml"
if [ -n "${TENZRO_FDROID_KEYSTORE:-}" ]; then
    (cd "$dir" && fdroid update)
    echo "$dir/repo (signed index)"
else
    (cd "$dir" && fdroid update --nosign)
    echo "UNSIGNED: no TENZRO_FDROID_KEYSTORE; this repository is for checking only" > "$dir/repo/UNSIGNED"
    echo "$dir/repo is UNSIGNED (set TENZRO_FDROID_KEYSTORE to sign its index)" >&2
    exit 3
fi
