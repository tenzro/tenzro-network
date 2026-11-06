# Build the Windows x86_64 release of Tenzro Control (the desktop app) natively:
# an .msi and an NSIS setup .exe, plus SHA256SUMS and a buildenv record, from a
# committed ref, npm ci and cargo --locked, with the toolchain pinned in
# rust-toolchain.toml.
#
# Assumes a build machine that already has MSVC build tools, rustup, standalone
# LLVM, Node 22 and git, and checks for each rather than installing it. The
# installers embed the WebView2 bootstrapper (bundle.windows in
# tauri.conf.json). They are unsigned unless bundle.windows.certificateThumbprint
# names a code-signing certificate in the machine's certificate store; nothing
# here reads a key.
#
# Usage (PowerShell, from anywhere):
#   scripts\release\build-control-windows.ps1 [-Ref <ref>] [-WorkDir C:\tenzro-build\control] [-Jobs 6]
#
# ASCII only. A parse error kills the script before its first line runs, so the
# failure appears as silence.
param(
    [string]$Ref = "HEAD",
    [string]$WorkDir = "C:\tenzro-build\control",
    [int]$Jobs = 6,
    [int]$MinFreeGB = 40
)
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repo
foreach ($tool in "git", "cargo", "rustc", "node", "npm", "clang") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "REFUSING: $tool is not on PATH" }
}
$pinned = (Select-String -Path rust-toolchain.toml -Pattern '^channel = "(.*)"').Matches[0].Groups[1].Value
if (-not ((rustc --version) -match " $pinned ")) { throw "REFUSING: rustc is not the pinned $pinned" }
if (-not ((node --version) -match '^v22\.')) { throw "REFUSING: Node 22 is required" }
$drive = (Split-Path -Qualifier $WorkDir).TrimEnd(':')
$free = [math]::Floor((Get-PSDrive $drive).Free / 1GB)
if ($free -lt $MinFreeGB) { throw "REFUSING: $free GB free on ${drive}:, need $MinFreeGB" }

$commit = (git rev-parse --verify "$Ref^{commit}")
$env:SOURCE_DATE_EPOCH = (git log -1 --format=%ct $commit)
$version = (git show "${commit}:apps/tenzro-control/src-tauri/tauri.conf.json" | ConvertFrom-Json).version
$name = "tenzro-control-windows-x86_64-$version"
$src = Join-Path $WorkDir "src-$($commit.Substring(0, 10))"
$dist = Join-Path $WorkDir "dist"
if (Test-Path $src) { Remove-Item -Recurse -Force $src }
New-Item -ItemType Directory -Force -Path $src, $dist | Out-Null
git archive --format=zip -o "$src.zip" $commit
Expand-Archive -Path "$src.zip" -DestinationPath $src
Remove-Item "$src.zip"

$env:CARGO_TARGET_DIR = Join-Path $WorkDir "target"
$env:CARGO_BUILD_JOBS = "$Jobs"
$env:CARGO_INCREMENTAL = "0"
Set-Location (Join-Path $src "apps\tenzro-control")
npm ci --no-audit --no-fund; if ($LASTEXITCODE) { throw "npm ci failed" }
npm test; if ($LASTEXITCODE) { throw "UI tests failed" }
npx tauri build --ci --bundles msi,nsis -- --locked; if ($LASTEXITCODE) { throw "tauri build failed" }

$bundle = Join-Path $env:CARGO_TARGET_DIR "release\bundle"
$msi = Get-ChildItem (Join-Path $bundle "msi\*.msi") | Select-Object -First 1
$nsis = Get-ChildItem (Join-Path $bundle "nsis\*-setup.exe") | Select-Object -First 1
Copy-Item $msi.FullName (Join-Path $dist "$name.msi") -Force
Copy-Item $nsis.FullName (Join-Path $dist "$name-setup.exe") -Force
$sums = foreach ($f in "$name.msi", "$name-setup.exe") {
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 (Join-Path $dist $f)).Hash.ToLower(), $f
}
[IO.File]::WriteAllLines((Join-Path $dist "$name.SHA256SUMS"), $sums)
@{
    artifact = $name; commit = $commit; version = $version; rust = $pinned
    builder = "Windows-x86_64"; built = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); locked = $true
} | ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $dist "$name.buildenv.json")
Set-Location $repo
Remove-Item -Recurse -Force $src
Write-Host "BUILD OK:"; Get-Content (Join-Path $dist "$name.SHA256SUMS")
