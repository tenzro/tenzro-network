# Build the Windows x86_64 release artifact (cpu, cuda or vulkan) of tenzro-node.exe
# and tenzro.exe natively, with Tenzro Control (the desktop app) beside them,
# from a committed ref, --locked, with the toolchain pinned in
# rust-toolchain.toml. Writes tenzro-node-windows-x86_64-<flavour>.zip
# and its .buildenv.json into -DistDir, on any drive with the free space.
#
# Assumes a build machine that already has
# MSVC build tools, the CUDA toolkit (cuda), the Vulkan SDK (vulkan), rustup,
# standalone LLVM and the .NET SDK (for Tenzro Control), and checks for each
# rather than installing it.
#
# Two things fail SILENTLY into a CPU-only binary that merely compiles:
#   - the one `cuda` feature covers llama.cpp and ONNX Runtime together; the
#     node refuses to start on an NVIDIA machine if its ORT lacks CUDA.
#   - CMAKE_CUDA_ARCHITECTURES / CUDAARCHS must stay UNSET. ggml picks the
#     architecture list itself; setting one produces a binary with no kernels
#     for the card present.
# The build asserts CUDA symbols at the end, so neither can pass unnoticed.
# The vulkan flavour compiles ggml's Vulkan shaders with the SDK's glslc and
# links vulkan-1.lib; the GPU driver supplies vulkan-1.dll at runtime. It
# asserts the Vulkan backend and the vulkan-1.dll import at the end.
#
# -NoInstallGate is for a build machine without the flavour's GPU (a cuda or
# vulkan build on a hosted runner): the archive is built, packed, checked for
# its backend and imports and unpacked to check that it holds its libraries,
# but the node is not run and no install record is written, since the node
# refuses to start there.
#
# Storage, not memory, is the constraint on this class of box, so the script
# refuses to start without real free space on the drive of -TargetDir
# (-MinFreeGB, 40 by default).
#
# ASCII only. A parse error kills the script before its first line runs, so the
# failure appears as silence.
param(
    [ValidateSet("cpu", "cuda", "vulkan")][string]$Flavour = "cuda",
    [string]$Ref = "HEAD",
    [string]$TargetDir = "D:\tz-target\release",
    [int]$Jobs = 6,
    [int]$MinFreeGB = 40,
    [string]$DistDir = "D:\dist",
    [switch]$NoInstallGate
)
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repo
$commit = (git rev-parse --verify "$Ref^{commit}")
# Read the commit time here: the source copy built from has no .git.
$commitTime = (git log -1 --format=%ct $commit)
$TargetDir = Join-Path $TargetDir $Flavour
# A committed tree, not the working tree: a Windows checkout carries CRLF and
# local edits that have no business in a release.
$src = Join-Path (Split-Path -Parent $TargetDir) "src-$commit"
if (-not (Test-Path $src)) {
    New-Item -ItemType Directory -Force -Path $src | Out-Null
    git archive --format=zip -o "$src.zip" $commit
    Expand-Archive -Path "$src.zip" -DestinationPath $src -Force
    Remove-Item "$src.zip"
}
Set-Location $src
Write-Output ("repo: " + $repo)
Write-Output ("ref: " + $commit + " flavour: " + $Flavour)

# --- toolchain -------------------------------------------------------------
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere not found: install Visual Studio Build Tools" }
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw "dotnet not found: install the .NET SDK (Tenzro Control is built with it)" }
$vsPath = & $vswhere -products * -latest -property installationPath
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found under $vsPath" }

# Import the MSVC environment: cl.exe, link.exe and the Windows SDK all arrive
# through it, and rustc's msvc target cannot link without them.
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
    if ($_ -match "^([^=]+)=(.*)$") { Set-Item -Path ("Env:" + $matches[1]) -Value $matches[2] }
}

$llvmBin = "C:\Program Files\LLVM\bin"
if (-not (Test-Path (Join-Path $llvmBin "libclang.dll"))) {
    throw "libclang.dll not found in $llvmBin -- bindgen needs standalone LLVM"
}
$env:LIBCLANG_PATH = $llvmBin

if ($Flavour -eq "cuda" -and -not $env:CUDA_PATH) {
    $cudaRoot = (Get-ChildItem "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA" -Directory |
                 Sort-Object Name -Descending | Select-Object -First 1).FullName
    if (-not $cudaRoot) { throw "no CUDA toolkit found" }
    $env:CUDA_PATH = $cudaRoot
}
if ($Flavour -eq "cuda") { $env:PATH = "$env:CUDA_PATH\bin;$env:PATH" }
if ($Flavour -eq "vulkan") {
    if (-not $env:VULKAN_SDK) {
        $vkRoot = (Get-ChildItem "C:\VulkanSDK" -Directory -ErrorAction SilentlyContinue |
                   Sort-Object Name -Descending | Select-Object -First 1).FullName
        if (-not $vkRoot) { throw "no Vulkan SDK found: install it (winget install KhronosGroup.VulkanSDK) or set VULKAN_SDK" }
        $env:VULKAN_SDK = $vkRoot
    }
    foreach ($need in @("Lib\vulkan-1.lib", "Bin\glslc.exe", "Include\vulkan\vulkan.hpp")) {
        if (-not (Test-Path (Join-Path $env:VULKAN_SDK $need))) { throw "Vulkan SDK at $env:VULKAN_SDK has no $need" }
    }
    $env:PATH = "$env:VULKAN_SDK\Bin;$env:PATH"
}
$env:PATH = "$llvmBin;$env:USERPROFILE\.cargo\bin;$env:PATH"
Remove-Item Env:\CMAKE_CUDA_ARCHITECTURES -ErrorAction SilentlyContinue
Remove-Item Env:\CUDAARCHS -ErrorAction SilentlyContinue

if ($Flavour -eq "cuda") { Write-Output ("nvcc:  " + ((& nvcc --version | Select-String "release").Line.Trim())) }
if ($Flavour -eq "vulkan") { Write-Output ("vulkan sdk: " + $env:VULKAN_SDK) }
$pinned = (Select-String -Path rust-toolchain.toml -Pattern '^channel = "(.*)"').Matches[0].Groups[1].Value
if (-not ((& rustc --version) -match [regex]::Escape($pinned))) { throw "REFUSING: rustc is not the pinned $pinned" }
Write-Output ("rustc: " + (& rustc --version))

# --- space -----------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
$drive = (Get-Item $TargetDir).PSDrive
$freeGB = [math]::Round($drive.Free / 1GB, 1)
if ($freeGB -lt $MinFreeGB) {
    throw "REFUSING: $freeGB GB free on $($drive.Name): and a CUDA build needs $MinFreeGB GB"
}
Write-Output ("target dir: $TargetDir ($freeGB GB free, $Jobs jobs)")
$env:CARGO_TARGET_DIR = $TargetDir
$env:CARGO_BUILD_JOBS = "$Jobs"
$env:CARGO_TERM_COLOR = "never"
# Keep line tables so the linker writes a .pdb beside each .exe; the .pdb ships in a separate debug zip.
$env:CARGO_PROFILE_RELEASE_STRIP = "none"
$env:CARGO_PROFILE_RELEASE_DEBUG = "line-tables-only"

# --- ONNX Runtime ----------------------------------------------------------
# The pinned library (packaging\onnxruntime.tsv), checked by hash and linked
# through ORT_LIB_LOCATION; the build downloads nothing.
$ortArgs = @((Join-Path $src "scripts\release\fetch-onnxruntime.py"), "--target", "x86_64-pc-windows-msvc",
    "--prefix", (Join-Path (Split-Path -Parent $TargetDir) "onnxruntime"), "--link-at", (Join-Path $src ".onnxruntime\host"))
if ($Flavour -eq "cuda") { $ortArgs += @("--feature", "cuda13,tensorrt,nvrtx,directml") }
& python @ortArgs
if ($LASTEXITCODE -ne 0) { throw "the pinned ONNX Runtime could not be fetched" }
$env:ORT_LIB_LOCATION = (Join-Path $src ".onnxruntime\host")

# --- build -----------------------------------------------------------------
$started = Get-Date
$cargoLog = Join-Path $TargetDir "cargo-build.log"
$cargoErr = Join-Path $TargetDir "cargo-build.err"
# Run cargo as its own process with its streams redirected to files, rather than
# piping. Cargo reports ordinary progress on stderr, and in Windows PowerShell a
# native command's stderr under ErrorActionPreference=Stop becomes a terminating
# error: the build then dies on its first "Compiling ..." line, which reads like
# a compile failure and is not one.
$proc = Start-Process -FilePath "cargo" -PassThru -Wait -NoNewWindow `
    -ArgumentList (@("build", "--release", "--locked",
        "-p", "tenzro-node", "--bin", "tenzro-node",
        "-p", "tenzro-cli", "--bin", "tenzro") + $(if ($Flavour -ne "cpu") { @("--features", "tenzro-node/$Flavour") } else { @() })) `
    -RedirectStandardOutput $cargoLog -RedirectStandardError $cargoErr
if ($proc.ExitCode -ne 0) {
    Write-Output "--- last errors ---"
    Get-Content $cargoErr, $cargoLog -EA SilentlyContinue |
        Select-String -Pattern "^error|error\[|panicked at|cannot find|failed to run|LIBCLANG|nvcc|glslc|Vulkan" |
        Select-Object -Last 25 | ForEach-Object { $_.Line }
    throw "cargo build failed with exit code $($proc.ExitCode)"
}
Write-Output ("built in " + [math]::Round(((Get-Date) - $started).TotalMinutes, 1) + " min")

# --- prove the flavour: a DONE marker is not proof --------------------------
$exe = Join-Path $TargetDir "release\tenzro-node.exe"
$bytes = [IO.File]::ReadAllBytes($exe)
$text = [Text.Encoding]::ASCII.GetString($bytes)
# "cudaMalloc" alone is not proof: the ONNX runtime allocator carries that name
# as a plain string in every build. The ggml CUDA backend is the real marker.
$hasCuda = $text.Contains("ggml_cuda")
$hasVulkan = $text.Contains("ggml_vulkan:")
if ($Flavour -eq "cuda" -and -not $hasCuda) { throw "binary has no CUDA symbols -- it is CPU-only" }
if ($Flavour -eq "vulkan" -and -not $hasVulkan) { throw "binary has no Vulkan backend -- it is CPU-only" }
if ($Flavour -ne "cuda" -and $hasCuda) { throw "$Flavour build carries CUDA symbols" }
if ($Flavour -ne "vulkan" -and $hasVulkan) { throw "$Flavour build carries the Vulkan backend" }
Write-Output ("tenzro-node.exe is " + [math]::Round($bytes.Length / 1MB, 1) + " MB")

# What the .exe needs at runtime: a dynamically linked cudart/cublas means the
# target box needs a matching toolkit, or those DLLs shipped beside it.
$dumpbin = Get-ChildItem "$vsPath\VC\Tools\MSVC" -Recurse -Filter dumpbin.exe -ErrorAction SilentlyContinue |
           Select-Object -First 1 -ExpandProperty FullName
$deps = @()
if ($dumpbin) {
    Write-Output "--- runtime DLL dependencies ---"
    $deps = & $dumpbin /DEPENDENTS $exe | Select-String -Pattern "\.dll" | ForEach-Object { $_.Line.Trim() }
    $deps
    # The Vulkan loader comes with the GPU driver; it must be an import, never bundled.
    if ($Flavour -eq "vulkan" -and -not ($deps -contains "vulkan-1.dll")) { throw "vulkan build does not import vulkan-1.dll" }
}

# --- package: deterministic entry times, SHA-256 recorded by the manifest ----
$name = "tenzro-node-windows-x86_64-$Flavour"
$stage = Join-Path $TargetDir "stage\$name"
Remove-Item -Recurse -Force (Join-Path $TargetDir "stage") -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $stage "bin") | Out-Null
Copy-Item $exe (Join-Path $stage "bin\tenzro-node.exe")
Copy-Item (Join-Path $TargetDir "release\tenzro.exe") (Join-Path $stage "bin\tenzro.exe")
# A statically linked ONNX Runtime still loads DirectML.dll and, in the CUDA
# build, its execution providers at run time from the binary's folder; they
# come from the pinned archive, not from the build.
Get-ChildItem $env:ORT_LIB_LOCATION -Filter *.dll -File | Copy-Item -Destination (Join-Path $TargetDir "release")
# The libraries the build leaves beside the binary, which the node loads from
# its own folder: DirectML.dll (ONNX Runtime on Windows imports it in every
# flavour, and an older Windows has none of its own or one too old) and, in the
# CUDA build, the ONNX Runtime execution providers. Without the providers an
# installed CUDA node has no ONNX path on its GPU. Only the CUDA flavour
# builds providers, so only it ships them.
$libs = @(Get-ChildItem (Join-Path $TargetDir "release") -File | Where-Object {
    $_.Name -ieq "DirectML.dll" -or ($Flavour -eq "cuda" -and $_.Name -like "onnxruntime*.dll") })
$libs | ForEach-Object { Copy-Item $_.FullName (Join-Path $stage "bin") }
$libNames = @($libs | ForEach-Object { $_.Name.ToLower() } | Sort-Object)
if ($Flavour -eq "cuda") {
    foreach ($need in "onnxruntime_providers_shared.dll", "onnxruntime_providers_cuda.dll") {
        if ($libNames -notcontains $need) { throw "REFUSING: the CUDA build left no $need beside the binary" }
    }
    # What the CUDA provider needs from the machine it is installed on (the
    # CUDA runtime and cuDNN are the machine's, never shipped).
    if ($dumpbin) {
        Write-Output "--- CUDA provider DLL dependencies ---"
        & $dumpbin /DEPENDENTS (Join-Path $TargetDir "release\onnxruntime_providers_cuda.dll") |
            Select-String -Pattern "\.dll" | ForEach-Object { $_.Line.Trim() }
    }
}
if (($deps | Where-Object { $_ -ieq "DirectML.dll" }) -and ($libNames -notcontains "directml.dll")) {
    throw "REFUSING: the binary imports DirectML.dll and the build left none beside it"
}
Write-Output ("libraries shipped: " + $(if ($libNames) { $libNames -join ", " } else { "none" }))
# The network profile a node started without --boot-nodes joins through (as the Linux and macOS archives ship it).
$profiles = Get-ChildItem (Join-Path $src "config\network") -Filter "*.toml" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^[0-9]+\.toml$' }
if (-not $profiles) { throw "REFUSING: no config\network\<chain_id>.toml to ship" }
New-Item -ItemType Directory -Force -Path (Join-Path $stage "share\network") | Out-Null
$profiles | ForEach-Object { Copy-Item $_.FullName (Join-Path $stage "share\network") }
# The web console `tenzro control --web` serves, at share\console beside bin\ (as the Linux and macOS archives ship it).
$console = Join-Path $src "apps\tenzro-control\web"
if (-not (Test-Path (Join-Path $console "index.html"))) { throw "REFUSING: no web console at apps\tenzro-control\web to ship" }
Copy-Item -Recurse $console (Join-Path $stage "share\console")
# Tenzro Control, the desktop app the installer opens: its model and wording
# (control-ffi from apps\tenzro-control\linux, as tenzro_control.dll) under the
# WinUI shell, built self-contained into control\. Each build runs as its own
# process with its streams in files, for the reason given at the cargo build.
function Invoke-Step([string]$What, [string]$Exe, [string[]]$Arguments) {
    $log = Join-Path $TargetDir "$What.log"
    $err = Join-Path $TargetDir "$What.err"
    $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput $log -RedirectStandardError $err
    if ($p.ExitCode -ne 0) {
        Get-Content $err, $log -EA SilentlyContinue | Select-String -Pattern "error" |
            Select-Object -Last 25 | ForEach-Object { $_.Line }
        throw "$What failed with exit code $($p.ExitCode)"
    }
}
$control = Join-Path $src "apps\tenzro-control"
$controlTarget = Join-Path $TargetDir "control"
Invoke-Step "control-ffi" "cargo" @("build", "--release", "--locked",
    "--manifest-path", (Join-Path $control "linux\Cargo.toml"), "-p", "control-ffi", "--target-dir", $controlTarget)
$native = Join-Path $control "windows\native\x64"
New-Item -ItemType Directory -Force -Path $native | Out-Null
Copy-Item (Join-Path $controlTarget "release\tenzro_control.dll") $native
# The window icon is generated from web/icon.svg and is not committed (.gitignore), so a
# fresh export of the commit has none and the C# compiler stops on it.
$icon = Join-Path $control "windows\icon.ico"
if (-not (Test-Path $icon)) {
    $shim = Join-Path $env:TEMP "tz-py3shim"
    New-Item -ItemType Directory -Force -Path $shim | Out-Null
    [IO.File]::WriteAllText((Join-Path $shim "python3"), "#!/bin/sh`nexec python `"`$@`"`n")
    $env:PATH = "$shim;$env:PATH"
    $sh = Join-Path $env:ProgramFiles "Git\bin\sh.exe"
    if (-not (Test-Path $sh)) { throw "REFUSING: Git for Windows sh.exe not found; it makes the window icon" }
    & $sh (Join-Path $control "tools\icons.sh") windows (Join-Path $control "windows")
    if (-not (Test-Path $icon)) { throw "REFUSING: icons.sh left no icon.ico" }
}
Invoke-Step "control-app" "dotnet" @("publish", (Join-Path $control "windows\TenzroControl.csproj"),
    "-c", "Release", "-r", "win-x64", "-p:Platform=x64", "--self-contained", "-o", (Join-Path $stage "control"))
# Tenzro Control's text is English only, so of the Windows App SDK's resource
# satellites (a folder of *.mui files per language) only en-US ships.
Get-ChildItem (Join-Path $stage "control") -Directory |
    Where-Object { $_.Name -ne "en-US" -and -not (Get-ChildItem $_.FullName -Recurse -File | Where-Object Extension -ne ".mui") } |
    Remove-Item -Recurse -Force
foreach ($need in "TenzroControl.exe", "tenzro_control.dll") {
    if (-not (Test-Path (Join-Path $stage "control\$need"))) { throw "REFUSING: the Tenzro Control build left no $need" }
}
# Authenticode, when this machine holds the release code-signing certificate:
# TENZRO_WINDOWS_SIGN_CERT names it by thumbprint (CurrentUser or LocalMachine
# store) and TENZRO_WINDOWS_TIMESTAMP_URL the RFC 3161 timestamp service that
# keeps each signature valid after the certificate expires. Each file must come
# out validly signed by that certificate. Without them nothing is signed.
function Invoke-CodeSign([string[]]$Paths) {
    if (-not $env:TENZRO_WINDOWS_SIGN_CERT) { Write-Output "unsigned: TENZRO_WINDOWS_SIGN_CERT is not set"; return }
    if (-not $env:TENZRO_WINDOWS_TIMESTAMP_URL) { throw "TENZRO_WINDOWS_SIGN_CERT is set without TENZRO_WINDOWS_TIMESTAMP_URL" }
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if (-not $signtool) {
        $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $signtool) { throw "signtool.exe not found: install the Windows SDK" }
    & $signtool sign /sha1 $env:TENZRO_WINDOWS_SIGN_CERT /fd SHA256 /tr $env:TENZRO_WINDOWS_TIMESTAMP_URL /td SHA256 $Paths
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE)" }
    foreach ($p in $Paths) {
        $sig = Get-AuthenticodeSignature -LiteralPath $p
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $env:TENZRO_WINDOWS_SIGN_CERT.ToUpper()) {
            throw "the signature of $p does not check out: $($sig.Status) $($sig.StatusMessage)"
        }
        Write-Output "signed by $($sig.SignerCertificate.Subject): $p"
    }
}
Invoke-CodeSign @((Join-Path $stage "bin\tenzro-node.exe"), (Join-Path $stage "bin\tenzro.exe"),
    (Join-Path $stage "control\TenzroControl.exe"), (Join-Path $stage "control\tenzro_control.dll"))
$epoch = [DateTimeOffset]::FromUnixTimeSeconds([long]$commitTime).UtcDateTime
Get-ChildItem -Recurse $stage | ForEach-Object { $_.LastWriteTimeUtc = $epoch }
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
$zip = Join-Path $DistDir "$name.zip"
Remove-Item $zip -ErrorAction SilentlyContinue
Compress-Archive -Path $stage -DestinationPath $zip
$lock = (Get-FileHash -Algorithm SHA256 (Join-Path $src "Cargo.lock")).Hash.ToLower()
$features = $(if ($Flavour -ne "cpu") { "tenzro-node/$Flavour" } else { "" })
@{ artifact = $name; commit = $commit; flavour = $Flavour; target = "x86_64-pc-windows-msvc";
   features = $features; rust = $pinned; cargo_lock_sha256 = $lock; container_image = "";
   builder = "Windows-x86_64"; built = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); locked = $true } |
    ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $DistDir "$name.buildenv.json")
# --- the packed archive, unpacked: it holds the libraries, and its own binary checks this machine ---
$gate = Join-Path $TargetDir "gate"
Remove-Item -Recurse -Force $gate -ErrorAction SilentlyContinue
Expand-Archive -Path $zip -DestinationPath $gate
$gateExe = Join-Path $gate "$name\bin\tenzro-node.exe"
foreach ($l in @("tenzro-node.exe", "tenzro.exe") + $libNames) {
    if (-not (Test-Path (Join-Path $gate "$name\bin\$l"))) { throw "the archive has no bin\$l" }
}
Write-Output ("archive holds: " + ((Get-ChildItem (Join-Path $gate "$name\bin") | ForEach-Object { $_.Name }) -join " "))
if (-not $NoInstallGate) {
    # The node logs to stderr; under ErrorActionPreference=Stop Windows PowerShell turns
    # redirected native stderr into a terminating error, so the redirect happens in cmd.
    $report = @(cmd.exe /c "`"$gateExe`" hardware 2>nul")
    $want = @{ cpu = "CPU"; cuda = "CUDA"; vulkan = "Vulkan" }[$Flavour]
    if (-not ($report -contains "build: $want")) { throw "install gate: the archive does not report a $want build: $($report -join '; ')" }
    if (-not ($report -contains "startup: ok")) { throw "install gate: the node would not start on this machine: $($report -join '; ')" }
    @{ artifact = $name; file = "$name.zip"; sha256 = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower();
       role = $(if ($Flavour -eq "cpu") { "cpu" } else { "gpu" }); host = "Windows-x86_64"; verdict = "pass";
       checked = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); report = $report } |
        ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $DistDir "$name.install.json")
}
Remove-Item -Recurse -Force $gate
# --- debug symbols: the .pdb files, matched to the .exe by their GUID, in a separate archive ---
$dbgStage = Join-Path $TargetDir "stage-debug\$name-debug"
Remove-Item -Recurse -Force (Join-Path $TargetDir "stage-debug") -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dbgStage | Out-Null
Get-ChildItem (Join-Path $TargetDir "release") -Filter "tenzro*.pdb" | ForEach-Object { Copy-Item $_.FullName $dbgStage }
if (-not (Get-ChildItem $dbgStage -Filter *.pdb)) { throw "no .pdb produced: the debug profile did not apply" }
Get-ChildItem -Recurse $dbgStage | ForEach-Object { $_.LastWriteTimeUtc = $epoch }
$dbgZip = Join-Path $DistDir "$name-debug.zip"
Remove-Item $dbgZip -ErrorAction SilentlyContinue
Compress-Archive -Path $dbgStage -DestinationPath $dbgZip
Write-Output ("BUILD OK: " + $zip)
