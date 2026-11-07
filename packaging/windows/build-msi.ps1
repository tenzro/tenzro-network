<#
.SYNOPSIS
  Builds the Tenzro MSI from a signed release archive (runs on Windows).

.DESCRIPTION
  Extracts the archive, verifies it holds exactly the two expected binaries,
  stages the license, notice and provenance files, and runs the WiX v4
  compiler. The binaries are packaged byte for byte; nothing is rebuilt.

  Requires: wix 4.x (dotnet tool) with the UI and Util extensions.
#>
param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$OutMsi,
    [Parameter(Mandatory)][string]$WorkDir,
    [string]$ExpectedZipSha256 = '',
    [string]$Version = '0.2.0',
    [string]$SourceCommit = '2892200028fd326e87a69ed7dba8bc9f110db8ff',
    [string]$PublicCommit = 'c78bd5fed6129a78285265c7de66b4572a5ceef4',
    [string]$LicensePath = '',
    [string]$NoticePath = '',
    [ValidateSet('low', 'medium', 'high')][string]$Compression = 'high'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $LicensePath) { $LicensePath = Join-Path $here 'LICENSE' }
if (-not $NoticePath) { $NoticePath = Join-Path $here 'NOTICE' }
$UpgradeCode = '6B1E5A52-3C0D-4F0B-9C5E-7A1D2F8B4E91'

function Get-Sha256([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }

# Stable name-based GUID (RFC 4122 version 5): same version gives the same ProductCode.
function New-NameGuid([string]$namespace, [string]$name) {
    $hex = $namespace.Replace('-', '')
    $ns = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $ns[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $data = $ns + [Text.Encoding]::UTF8.GetBytes($name)
    $h = [Security.Cryptography.SHA1]::Create().ComputeHash($data)
    $b = $h[0..15]
    $b[6] = ($b[6] -band 0x0F) -bor 0x50
    $b[8] = ($b[8] -band 0x3F) -bor 0x80
    $s = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
    return ('{0}-{1}-{2}-{3}-{4}' -f $s.Substring(0, 8), $s.Substring(8, 4), $s.Substring(12, 4), $s.Substring(16, 4), $s.Substring(20, 12)).ToUpper()
}

if (-not (Test-Path -LiteralPath $ZipPath)) { throw "archive not found: $ZipPath" }
$zipSha = Get-Sha256 $ZipPath
if ($ExpectedZipSha256 -and ($zipSha -ne $ExpectedZipSha256.ToLower())) {
    throw "archive sha256 mismatch: got $zipSha expected $ExpectedZipSha256"
}

if (Test-Path -LiteralPath $WorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Path $WorkDir | Out-Null
$extract = Join-Path $WorkDir 'extract'
$stage = Join-Path $WorkDir 'stage'
New-Item -ItemType Directory -Path $stage | Out-Null
Expand-Archive -LiteralPath $ZipPath -DestinationPath $extract

$top = Get-ChildItem -LiteralPath $extract -Directory
if ($top.Count -ne 1) { throw 'unexpected archive layout (expected one top-level directory)' }
$payload = $top[0].FullName
$files = Get-ChildItem -LiteralPath $payload -Recurse -File | ForEach-Object { $_.FullName.Substring($payload.Length + 1).ToLower() } | Sort-Object
if ($files.Count -ne 2 -or ($files -notcontains 'bin\tenzro.exe') -or ($files -notcontains 'bin\tenzro-node.exe')) {
    throw "unexpected archive contents: $($files -join ', ')"
}
$exeSha = @{}
foreach ($f in $files) { $exeSha[$f] = Get-Sha256 (Join-Path $payload $f) }

# License and notice (Apache-2.0)
Copy-Item -LiteralPath $LicensePath -Destination (Join-Path $stage 'LICENSE.txt')
Copy-Item -LiteralPath $NoticePath -Destination (Join-Path $stage 'NOTICE.txt')

# Plain RTF for the license page
$lic = [IO.File]::ReadAllText($LicensePath)
$sb = New-Object Text.StringBuilder
[void]$sb.Append('{\rtf1\ansi\deff0{\fonttbl{\f0\fmodern Courier New;}}\f0\fs18 ')
foreach ($ch in $lic.ToCharArray()) {
    switch ($ch) {
        '\' { [void]$sb.Append('\\') }
        '{' { [void]$sb.Append('\{') }
        '}' { [void]$sb.Append('\}') }
        "`n" { [void]$sb.Append("\par`r`n") }
        "`r" { }
        default { if ([int]$ch -gt 126) { [void]$sb.Append('\u' + [int]$ch + '?') } else { [void]$sb.Append($ch) } }
    }
}
[void]$sb.Append('}')
[IO.File]::WriteAllText((Join-Path $stage 'License.rtf'), $sb.ToString(), [Text.Encoding]::ASCII)

# Provenance
$prov = @"
Tenzro $Version (Windows x86_64, CUDA build)

This package repackages the released binaries unchanged.

release source commit : $SourceCommit
public repository head: $PublicCommit
  (github.com/tenzro/tenzro-network)
source archive        : $(Split-Path -Leaf $ZipPath)
source archive sha256 : $zipSha

binary sha256:
  bin\tenzro.exe       $($exeSha['bin\tenzro.exe'])
  bin\tenzro-node.exe  $($exeSha['bin\tenzro-node.exe'])

Verify the download against the release signature (cosign on SHA256SUMS)
as described in the release verification guide before installing.

This installer starts no service and joins no network. It adds the bin
folder to PATH only if you choose that. Run tenzro-check to test whether
this machine can run the CUDA build.
"@
[IO.File]::WriteAllText((Join-Path $stage 'PROVENANCE.txt'), ($prov -replace "`r?`n", "`r`n"), [Text.Encoding]::ASCII)

$productCode = '{' + (New-NameGuid $UpgradeCode "tenzro-windows-x86_64-cuda-$Version") + '}'

$wix = Get-Command wix -ErrorAction Stop
Write-Host "wix: $(& wix --version)"
Write-Host "ProductCode: $productCode  Version: $Version"


$outDir = Split-Path -Parent $OutMsi
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Validation rules suppressed below (reviewed):
#   ICE34      ADDTOPATH is deliberately unset until the first action after AppSearch
#              (so a previous choice can be kept on upgrade); the dialog only runs after that.
#   ICE38/43/57  the Start menu shortcuts are all-users (per-machine) and use an HKLM key path.
& wix build -arch x64 -o $OutMsi `
    -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext `
    -d "Version=$Version" -d "ProductCode=$productCode" -d "Compression=$Compression" `
    -d "PayloadDir=$payload" -d "StageDir=$stage" -d "ScriptDir=$here" `
    -d "SourceCommit=$SourceCommit" -d "PublicCommit=$PublicCommit" -d "ArchiveSha256=$zipSha" `
    (Join-Path $here 'Tenzro.wxs')
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }

& wix msi validate -sice ICE34 -sice ICE38 -sice ICE43 -sice ICE57 $OutMsi
if ($LASTEXITCODE -ne 0) { throw "MSI validation failed ($LASTEXITCODE)" }

Remove-Item -LiteralPath $WorkDir -Recurse -Force
$len = (Get-Item -LiteralPath $OutMsi).Length
Write-Host "MSI: $OutMsi"
Write-Host "size: $len"
Write-Host "sha256: $(Get-Sha256 $OutMsi)"
