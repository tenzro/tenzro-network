#!/usr/bin/env bash
# The winget manifests for a release's Windows installer, for a pull request to the community
# catalogue (microsoft/winget-pkgs).
#
#   gen-manifests.sh <msi> <version> <download-url-of-the-msi> <out-dir>
#
# Writes <out-dir>/manifests/t/Tenzro/Tenzro/<version>/ with the version, installer and en-US
# locale manifests. winget checks the installer against the digest written here.
set -euo pipefail
msi=${1:?usage: gen-manifests.sh <msi> <version> <download-url> <out-dir>}
ver=${2:?}; url=${3:?}; out=${4:?}
[ -f "$msi" ] || { echo "REFUSING: no installer at $msi" >&2; exit 1; }
sha=$(sha256sum "$msi" | awk '{print toupper($1)}')
dir="$out/manifests/t/Tenzro/Tenzro/$ver"
mkdir -p "$dir"
schema=1.6.0
cat > "$dir/Tenzro.Tenzro.yaml" <<EOF
PackageIdentifier: Tenzro.Tenzro
PackageVersion: $ver
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $schema
EOF
cat > "$dir/Tenzro.Tenzro.installer.yaml" <<EOF
PackageIdentifier: Tenzro.Tenzro
PackageVersion: $ver
MinimumOSVersion: 10.0.17763.0
InstallerType: msi
Scope: machine
UpgradeBehavior: install
Installers:
- Architecture: x64
  InstallerUrl: $url
  InstallerSha256: $sha
ManifestType: installer
ManifestVersion: $schema
EOF
cat > "$dir/Tenzro.Tenzro.locale.en-US.yaml" <<EOF
PackageIdentifier: Tenzro.Tenzro
PackageVersion: $ver
PackageLocale: en-US
Publisher: Tenzro
PublisherUrl: https://tenzro.com
PackageName: Tenzro
PackageUrl: https://tenzro.com
License: Apache-2.0
ShortDescription: Run a Tenzro node, with the tenzro terminal app.
Moniker: tenzro
Tags:
- node
- tenzro
ManifestType: defaultLocale
ManifestVersion: $schema
EOF
echo "$dir"
