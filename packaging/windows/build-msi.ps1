<#
.SYNOPSIS
  Builds the Tenzro MSI from a signed release archive (runs on Windows).

.DESCRIPTION
  Extracts the archive, verifies it holds the two programs, the libraries they
  load from their own folder and the network profile, and nothing else,
  stages the license, notice and provenance files, and runs the WiX v4
  compiler. The binaries are packaged byte for byte; nothing is rebuilt.

  Requires: wix 4.x (dotnet tool) with the UI and Util extensions.

#>
param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$OutMsi,
    [Parameter(Mandatory)][string]$WorkDir,
    [string]$ExpectedZipSha256 = '',
    [string]$Version = '',
    [string]$SourceCommit = 'unknown',
    [string]$PublicCommit = 'unknown',
    [string]$LicensePath = '',
    [string]$NoticePath = '',
    [ValidateSet('low', 'medium', 'high')][string]$Compression = 'high',
    [ValidateSet('cuda', 'cpu')][string]$Flavour = 'cuda'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Version) {
    # Run from a checkout: the version of the node, as the other packages take it.
    $nodeToml = Join-Path $here '..\..\crates\tenzro-node\Cargo.toml'
    if (Test-Path -LiteralPath $nodeToml) {
        $m = Select-String -LiteralPath $nodeToml -Pattern '^version = "(.*)"' | Select-Object -First 1
        if ($m) { $Version = $m.Matches[0].Groups[1].Value }
    }
    if (-not $Version) { throw 'no -Version given and no crates\tenzro-node\Cargo.toml to read it from' }
}
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
# The archive holds the two programs, the libraries they load from their own
# folder, the network profile, the web console `tenzro control --web` serves
# (share\console, with its scripts in share\console\src) and Tenzro Control, the
# desktop app, with everything its self-contained build keeps beside it
# (control\, at any depth). Anything else is not repackaged blindly.
$libFiles = @($files | Where-Object { $_ -match '^bin\\(onnxruntime[a-z0-9_]*|directml)\.dll$' })
$netFiles = @($files | Where-Object { $_ -match '^share\\network\\[0-9]+\.toml$' })
$consoleFiles = @($files | Where-Object { $_ -match '^share\\console\\[a-z0-9_][a-z0-9_.-]*$' })
$consoleSrcFiles = @($files | Where-Object { $_ -match '^share\\console\\src\\[a-z0-9_][a-z0-9_.-]*\.js$' })
$controlFiles = @($files | Where-Object { $_ -match '^control\\([a-z0-9_][a-z0-9_.-]*\\)*[a-z0-9_][a-z0-9_.-]*$' })
$known = @('bin\tenzro.exe', 'bin\tenzro-node.exe') + $libFiles + $netFiles + $consoleFiles + $consoleSrcFiles + $controlFiles
$unknown = @($files | Where-Object { $known -notcontains $_ })
if (($files -notcontains 'bin\tenzro.exe') -or ($files -notcontains 'bin\tenzro-node.exe') -or $unknown) {
    throw "unexpected archive contents: $($files -join ', ')"
}
if (-not $netFiles) { throw 'the archive ships no network profile (share\network\<chain_id>.toml)' }
foreach ($need in 'control\tenzrocontrol.exe', 'control\tenzro_control.dll') {
    if ($controlFiles -notcontains $need) { throw "the archive has no Tenzro Control ($need)" }
}
# console check begin
# Every archive ships the web console; an MSI without it would also carry empty component groups.
function Assert-Console([string[]]$Console, [string[]]$ConsoleSrc) {
    if ($Console -notcontains 'share\console\index.html') { throw 'the archive ships no web console (share\console\index.html)' }
    if (-not $ConsoleSrc) { throw 'the archive ships no web console scripts (share\console\src\*.js)' }
}
# console check end
Assert-Console $consoleFiles $consoleSrcFiles
$FlavourLabel = if ($Flavour -eq 'cuda') { 'CUDA' } else { 'CPU' }
if ($Flavour -eq 'cuda') {
    foreach ($need in 'bin\onnxruntime_providers_shared.dll', 'bin\onnxruntime_providers_cuda.dll') {
        if ($libFiles -notcontains $need) { throw "the CUDA archive has no $need" }
    }
} elseif ($libFiles | Where-Object { $_ -match 'providers_cuda' }) {
    throw 'a CUDA archive was given with -Flavour cpu'
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
Tenzro $Version (Windows x86_64, $FlavourLabel build)

This package repackages the released binaries unchanged.

release source commit : $SourceCommit
public repository head: $PublicCommit
  (github.com/tenzro/tenzro-network)
source archive        : $(Split-Path -Leaf $ZipPath)
source archive sha256 : $zipSha

file sha256:
$((@($files | ForEach-Object { "  {0}  {1}" -f $exeSha[$_], $_ })) -join "`n")

Verify the download against the release signature (cosign on SHA256SUMS)
as described in the release verification guide before installing.

This installer starts no service and joins no network. It adds the bin
folder to PATH only if you choose that. Run tenzro-check to test whether
this machine can run the $FlavourLabel build.
"@
[IO.File]::WriteAllText((Join-Path $stage 'PROVENANCE.txt'), ($prov -replace "`r?`n", "`r`n"), [Text.Encoding]::ASCII)

$productCode = '{' + (New-NameGuid $UpgradeCode "tenzro-windows-x86_64-$Flavour-$Version") + '}'

# The libraries and network profiles differ from archive to archive, so their
# components are written here and compiled with Tenzro.wxs.
function New-FileComponents([string]$GroupId, [string]$DirectoryId, [string]$Prefix, [string[]]$Relative) {
    $x = "    <ComponentGroup Id=`"$GroupId`" Directory=`"$DirectoryId`">`r`n"
    foreach ($rel in $Relative) {
        # The archive listing above is lower-cased; the file keeps its own name.
        $file = Get-ChildItem -LiteralPath (Split-Path -Parent (Join-Path $payload $rel)) -File |
                Where-Object { $_.Name -ieq (Split-Path -Leaf $rel) } | Select-Object -First 1
        $id = $Prefix + ($file.Name -replace '[^A-Za-z0-9_.]', '_')
        $source = [Security.SecurityElement]::Escape($file.FullName)
        $x += "      <Component Id=`"Cmp$id`" Bitness=`"always64`">`r`n"
        $x += "        <File Id=`"$id`" Source=`"$source`" KeyPath=`"yes`" />`r`n"
        $x += "      </Component>`r`n"
    }
    return $x + "    </ComponentGroup>`r`n"
}
# Tenzro Control is a tree, so its folders are written here too, under
# CONTROLDIR. Ids come from a digest of the path: stable from release to
# release, unique, and short enough for WiX.
function Get-PathId([string]$Prefix, [string]$Rel) {
    $digest = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Rel.ToLower()))
    return $Prefix + (-join ($digest[0..11] | ForEach-Object { $_.ToString('x2') }))
}
function New-TreeComponents([string]$GroupId, [string]$DirectoryId, [string]$Root) {
    $base = Join-Path $payload $Root
    $dirOf = { param($rel) $up = Split-Path -Parent $rel; if ($up) { Get-PathId 'CtlDir_' $up } else { $DirectoryId } }
    $x = ''
    foreach ($d in (Get-ChildItem -LiteralPath $base -Recurse -Directory | Sort-Object { $_.FullName.Length })) {
        $rel = $d.FullName.Substring($base.Length + 1)
        $name = [Security.SecurityElement]::Escape($d.Name)
        $x += "    <DirectoryRef Id=`"$(& $dirOf $rel)`"><Directory Id=`"$(Get-PathId 'CtlDir_' $rel)`" Name=`"$name`" /></DirectoryRef>`r`n"
    }
    $x += "    <ComponentGroup Id=`"$GroupId`">`r`n"
    foreach ($f in (Get-ChildItem -LiteralPath $base -Recurse -File | Sort-Object FullName)) {
        $rel = $f.FullName.Substring($base.Length + 1)
        $id = Get-PathId 'Ctl_' $rel
        $source = [Security.SecurityElement]::Escape($f.FullName)
        $x += "      <Component Id=`"Cmp$id`" Directory=`"$(& $dirOf $rel)`" Bitness=`"always64`">`r`n"
        $x += "        <File Id=`"$id`" Source=`"$source`" KeyPath=`"yes`" />`r`n"
        $x += "      </Component>`r`n"
    }
    return $x + "    </ComponentGroup>`r`n"
}
$payloadWxs = Join-Path $WorkDir 'Payload.wxs'
$fragment = "<Wix xmlns=`"http://wixtoolset.org/schemas/v4/wxs`">`r`n  <Fragment>`r`n" +
    (New-FileComponents 'PayloadLibs' 'BINDIR' 'Lib_' $libFiles) +
    (New-FileComponents 'NetworkProfiles' 'NETWORKDIR' 'Net_' $netFiles) +
    (New-FileComponents 'ConsoleFiles' 'CONSOLEDIR' 'Con_' $consoleFiles) +
    (New-FileComponents 'ConsoleSrcFiles' 'CONSOLESRCDIR' 'ConSrc_' $consoleSrcFiles) +
    (New-TreeComponents 'ControlFiles' 'CONTROLDIR' 'control') +
    "  </Fragment>`r`n</Wix>`r`n"
[IO.File]::WriteAllText($payloadWxs, $fragment, [Text.Encoding]::ASCII)

$wix = Get-Command wix -ErrorAction Stop
Write-Host "wix: $(& wix --version)"
Write-Host "ProductCode: $productCode  Version: $Version"


$outDir = Split-Path -Parent $OutMsi
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Validation rules suppressed below (reviewed):
#   ICE34      ADDTOPATH is deliberately unset until the first action after AppSearch
#              (so a previous choice can be kept on upgrade); the dialog only runs after that.
#   ICE38/43/57  the Start menu shortcuts are all-users (per-machine) and use an HKLM key path.
# A failed build leaves no MSI behind, not even one from an earlier run.
Remove-Item -LiteralPath $OutMsi -ErrorAction SilentlyContinue
& wix build -arch x64 -o $OutMsi `
    -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext `
    -d "Version=$Version" -d "Flavour=$FlavourLabel" -d "ProductCode=$productCode" -d "Compression=$Compression" `
    -d "PayloadDir=$payload" -d "StageDir=$stage" -d "ScriptDir=$here" `
    -d "SourceCommit=$SourceCommit" -d "PublicCommit=$PublicCommit" -d "ArchiveSha256=$zipSha" `
    (Join-Path $here 'Tenzro.wxs') $payloadWxs
if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $OutMsi -ErrorAction SilentlyContinue; throw "wix build failed ($LASTEXITCODE)" }

& wix msi validate -sice ICE34 -sice ICE38 -sice ICE43 -sice ICE57 $OutMsi
# An MSI that fails validation is not left where a later step could install it.
if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $OutMsi -ErrorAction SilentlyContinue; throw "MSI validation failed ($LASTEXITCODE)" }
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
Invoke-CodeSign @($OutMsi)


Remove-Item -LiteralPath $WorkDir -Recurse -Force
$len = (Get-Item -LiteralPath $OutMsi).Length
Write-Host "MSI: $OutMsi"
Write-Host "size: $len"
Write-Host "sha256: $(Get-Sha256 $OutMsi)"
