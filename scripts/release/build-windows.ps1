# Build the Windows x86_64 release artifact (cpu, cuda or vulkan) of tenzro-node.exe
# and tenzro.exe natively, from a committed ref, --locked, with the toolchain
# pinned in rust-toolchain.toml. Writes tenzro-node-windows-x86_64-<flavour>.zip
# and its .buildenv.json into -DistDir, on any drive with the free space.
#
# Assumes a build machine that already has
# MSVC build tools, the CUDA toolkit (cuda), the Vulkan SDK (vulkan), rustup and
# standalone LLVM, and checks for each rather than installing it.
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
    [string]$DistDir = "D:\dist"
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
# --- install gate: the packed archive, unpacked and checked by its own binary on this machine ---
$gate = Join-Path $TargetDir "gate"
Remove-Item -Recurse -Force $gate -ErrorAction SilentlyContinue
Expand-Archive -Path $zip -DestinationPath $gate
# The node logs to stderr; under ErrorActionPreference=Stop Windows PowerShell turns
# redirected native stderr into a terminating error, so the redirect happens in cmd.
$gateExe = Join-Path $gate "$name\bin\tenzro-node.exe"
$report = @(cmd.exe /c "`"$gateExe`" hardware 2>nul")
$want = @{ cpu = "CPU"; cuda = "CUDA"; vulkan = "Vulkan" }[$Flavour]
if (-not ($report -contains "build: $want")) { throw "install gate: the archive does not report a $want build: $($report -join '; ')" }
if (-not ($report -contains "startup: ok")) { throw "install gate: the node would not start on this machine: $($report -join '; ')" }
Remove-Item -Recurse -Force $gate
@{ artifact = $name; file = "$name.zip"; sha256 = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower();
   role = $(if ($Flavour -eq "cpu") { "cpu" } else { "gpu" }); host = "Windows-x86_64"; verdict = "pass";
   checked = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); report = $report } |
    ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $DistDir "$name.install.json")
Write-Output ("BUILD OK: " + $zip)
