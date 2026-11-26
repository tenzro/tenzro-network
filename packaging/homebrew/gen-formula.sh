#!/usr/bin/env bash
# The Homebrew formula for a release, for Tenzro's own tap: the node and the terminal app from the
# release's macOS archives, checked against the release's SHA256SUMS.
#
#   gen-formula.sh <dist-dir> <version> <download-url-of-the-release> <tap-dir>
#
# Writes <tap-dir>/Formula/tenzro.rb, and <tap-dir>/Casks/tenzro-control.rb for Tenzro Control,
# the desktop app the same archives carry in control/. The archives are the release's own; neither
# file adds a signature of its own, and Homebrew checks each archive against the digest written
# here. The cask depends on the formula by the tap's name, TENZRO_HOMEBREW_TAP (default tenzro/tap,
# the repository tenzro/homebrew-tap).
set -euo pipefail
dist=$(cd "${1:?usage: gen-formula.sh <dist-dir> <version> <download-url> <tap-dir>}" && pwd)
ver=${2:?}; base=${3:?}; tap=${4:?}
digest() {
    local s; s=$(awk -v f="$1" '$2==f {print $1}' "$dist/SHA256SUMS")
    [ -n "$s" ] || { echo "REFUSING: $dist/SHA256SUMS does not list $1" >&2; exit 1; }
    echo "$s"
}
arm=tenzro-node-macos-aarch64-metal.tar.gz
intel=tenzro-node-macos-x86_64-cpu.tar.gz
arm_sha=$(digest "$arm"); intel_sha=$(digest "$intel")
mkdir -p "$tap/Formula"
cat > "$tap/Formula/tenzro.rb" <<EOF
class Tenzro < Formula
  desc "Run a Tenzro node, with the tenzro terminal app"
  homepage "https://tenzro.com"
  version "$ver"
  license "Apache-2.0"

  on_arm do
    url "${base%/}/$arm"
    sha256 "$arm_sha"
  end
  on_intel do
    url "${base%/}/$intel"
    sha256 "$intel_sha"
  end

  depends_on :macos

  def install
    # The binaries read the network profile beside them, so the archive stays whole but for
    # Tenzro Control, which the tenzro-control cask installs.
    rm_r "control"
    libexec.install Dir["*"]
    bin.install_symlink libexec/"bin/tenzro", libexec/"bin/tenzro-node"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tenzro --version")
  end
end
EOF
mkdir -p "$tap/Casks"
cat > "$tap/Casks/tenzro-control.rb" <<EOF
cask "tenzro-control" do
  arch arm: "aarch64-metal", intel: "x86_64-cpu"

  version "$ver"
  sha256 arm:   "$arm_sha",
         intel: "$intel_sha"

  url "${base%/}/tenzro-node-macos-#{arch}.tar.gz"
  name "Tenzro Control"
  desc "Set up and run a Tenzro node"
  homepage "https://tenzro.com"

  depends_on macos: ">= :tahoe"
  depends_on formula: "${TENZRO_HOMEBREW_TAP:-tenzro/tap}/tenzro"

  app "tenzro-node-macos-#{arch}/control/Tenzro Control.app"
end
EOF
echo "$tap/Formula/tenzro.rb"
echo "$tap/Casks/tenzro-control.rb"
