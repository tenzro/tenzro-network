<#
.SYNOPSIS
  Hardware check for the Tenzro node. Check only: it changes nothing.

.DESCRIPTION
  Runs "tenzro-node.exe hardware" (the same check the node runs at startup,
  without starting a node) with a 60 second limit and a throw-away data
  directory, then prints the result in plain language.

  Exit codes: 0 = ready, 1 = not ready on this machine, 2 = the check could
  not run (missing binary, timeout). The installer never depends on this
  exit code; it never fails an install.
#>
param(
    [string]$NodeExe = (Join-Path $PSScriptRoot 'bin\tenzro-node.exe'),
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'

function Strip-Ansi([string]$s) {
    if ($null -eq $s) { return '' }
    return ([regex]::Replace($s, '\x1b\[[0-9;]*[A-Za-z]', '')).TrimEnd()
}

if (-not (Test-Path -LiteralPath $NodeExe)) {
    Write-Host "CHECK FAILED: cannot find tenzro-node.exe at $NodeExe"
    exit 2
}

# Throw-away data directory so nothing is written to the user profile.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('tenzro-check-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

$proc = $null
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $NodeExe
    $psi.Arguments = 'hardware'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $tmp
    $psi.EnvironmentVariables['TENZRO_DATA_DIR'] = $tmp

    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { $proc.Kill() } catch { }
        Write-Host "CHECK FAILED: the hardware check did not finish within $TimeoutSeconds seconds and was stopped."
        Write-Host "You can still use the tenzro CLI. Run tenzro-check again later."
        exit 2
    }
    $proc.WaitForExit()
    $rc = $proc.ExitCode
    $stdout = $outTask.Result
    $stderr = $errTask.Result
}
catch {
    Write-Host "CHECK FAILED: could not run the hardware check ($($_.Exception.Message))."
    exit 2
}
finally {
    if ($proc) { $proc.Dispose() }
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# Parse the "key: value" lines the binary prints on standard output.
$kv = @{}
foreach ($line in ($stdout -split "`r?`n")) {
    $l = Strip-Ansi $line
    if ($l -match '^(build|gpus|onnx|startup):\s*(.*)$') { $kv[$Matches[1]] = $Matches[2].Trim() }
}

# GPU model name, if the runtime reported one.
$gpuName = $null
foreach ($line in ((($stdout + "`n" + $stderr)) -split "`r?`n")) {
    $l = Strip-Ansi $line
    if ($l -match 'Device\s+0:\s*([^,]+),') { $gpuName = $Matches[1].Trim(); break }
}

$build = $kv['build']
$gpus = 0
if ($kv.ContainsKey('gpus')) { [void][int]::TryParse($kv['gpus'], [ref]$gpus) }
$startup = $kv['startup']

if ($kv.Count -eq 0) {
    Write-Host 'CHECK FAILED: the hardware check printed no result.'
    $tail = (($stdout + "`n" + $stderr) -split "`r?`n" | ForEach-Object { Strip-Ansi $_ } | Where-Object { $_ } | Select-Object -Last 4)
    foreach ($t in $tail) { Write-Host "  $t" }
    exit 2
}

$ready = ($rc -eq 0) -and ($startup -like 'ok*')
Write-Host ''
if ($ready) {
    if ($build -eq 'CUDA') {
        $what = if ($gpus -eq 1) { '1 NVIDIA GPU' } else { "$gpus NVIDIA GPUs" }
        if ($gpuName) { $what = "$what ($gpuName)" }
        Write-Host "OK: this is the CUDA build and it found $what; GPU model serving is available."
    }
    else {
        Write-Host "OK: this is the $build build and this machine can run it. No NVIDIA GPU is required for this build."
    }
    exit 0
}

# Not ready: report the binary's own words.
$words = $startup
if (-not $words) {
    $words = (($stderr -split "`r?`n" | ForEach-Object { Strip-Ansi $_ } | Where-Object { $_ -match '^Error:' } | Select-Object -First 1))
}
if (-not $words) { $words = "exit code $rc" }
$words = $words -replace '^refused\s*\(', '' -replace '\)\s*$', ''

if ($build -eq 'CUDA' -and $gpus -eq 0) {
    Write-Host "NOT READY: this package is the CUDA build but this machine has no usable NVIDIA GPU or driver ($words)."
    Write-Host 'You can still use the tenzro CLI; to serve models install the CPU build or install the NVIDIA driver, then run tenzro-check again.'
}
else {
    Write-Host "NOT READY: the node would refuse to start on this machine ($words)."
    Write-Host 'You can still use the tenzro CLI. Fix the issue above, then run tenzro-check again.'
}
exit 1
