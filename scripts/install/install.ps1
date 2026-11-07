# Tenzro installer for Windows (x86_64). PowerShell 5.1 or 7.
#
#   irm https://downloads.tenzro.com/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://downloads.tenzro.com/install.ps1))) -DryRun
#
# Same steps as install.sh, and it stops at the first failure:
#   1. picks the archive for this machine from the release's SHA256SUMS
#   2. verifies SHA256SUMS.sig (ECDSA P-256, SHA-256) against the release key embedded
#      below, whose fingerprint is checked first, using .NET (no openssl needed)
#   3. verifies the archive's SHA-256 against that signed list
#   4. unpacks under PREFIX\install\versions\ and runs the binary's own hardware check
#   5. points PREFIX\install\current at it and offers to put its bin folder on your PATH
# Nothing is installed unless 2 and 3 pass. No administrator rights needed.
#
# This script itself is covered by TLS only. Its SHA-256 is published beside it
# (install.ps1.sha256). To avoid trusting it, follow docs/VERIFY-DOWNLOAD.md.
#
# Options: -Version V  -Prefix DIR  -Target NAME  -From DIR (offline)  -BaseUrl URL
#          -DryRun  -Uninstall  -ModifyPath  -NoModifyPath
param(
    [string]$Version = '', [string]$Prefix = '', [string]$Target = '', [string]$From = '',
    [string]$BaseUrl = '', [switch]$DryRun, [switch]$Uninstall, [switch]$ModifyPath, [switch]$NoModifyPath
)

function Install-Tenzro {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # Windows PowerShell 5.1 downloads are very slow with the progress bar
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

    $KeyFpr = 'c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d'
    $PubKey = @'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3/NYEWx6w1OdV23xU656MhkpzxNM
PAP5jhmCYs7mWBx/W6lVL7cgwsTRlzcNq8iMIyU2lPMsmGNC7nZkxpaTZA==
-----END PUBLIC KEY-----
'@
    if (-not $BaseUrl) { $BaseUrl = if ($env:TENZRO_DOWNLOAD_BASE) { $env:TENZRO_DOWNLOAD_BASE } else { 'https://downloads.tenzro.com' } }
    $BaseUrl = $BaseUrl.TrimEnd('/')
    if (-not $Prefix) { $Prefix = if ($env:TENZRO_HOME) { $env:TENZRO_HOME } else { Join-Path $HOME '.tenzro' } }
    $Inst = Join-Path $Prefix 'install'
    $Current = Join-Path $Inst 'current'
    $BinDir = Join-Path $Current 'bin'
    $t0 = Get-Date

    $useColor = (-not $env:NO_COLOR) -and (-not [Console]::IsOutputRedirected) -and ($Host.UI.SupportsVirtualTerminal -or $PSVersionTable.PSVersion.Major -ge 7)
    $esc = [char]27
    $acc = if ($useColor) { "$esc[38;5;110m" } else { '' }
    $dim = if ($useColor) { "$esc[2m" } else { '' }
    $off = if ($useColor) { "$esc[0m" } else { '' }
    function Row($k, $v) { Write-Host ('  {0}{1,-11}{2} {3}' -f $dim, $k, $off, $v) }
    function Fail($what, $why, $fix) {
        $m = "`nerror: $what"
        if ($why) { $m += "`n  why:  $why" }
        if ($fix) { $m += "`n  fix:  $fix" }
        $m += "`n  Nothing was installed or changed on this machine.`n"
        throw $m
    }
    function Get-UserPath { [Environment]::GetEnvironmentVariable('Path', 'User') }
    function Remove-FromUserPath($dir) {
        $p = Get-UserPath
        if ($p) {
            $keep = ($p -split ';') | Where-Object { $_ -and ($_.TrimEnd('\') -ne $dir.TrimEnd('\')) }
            [Environment]::SetEnvironmentVariable('Path', ($keep -join ';'), 'User')
        }
    }

    if ($Uninstall) {
        if (Test-Path $Current) { (Get-Item $Current).Delete() 2>$null; if (Test-Path $Current) { cmd /c rmdir "$Current" } }
        $had = Test-Path $Inst
        if ($had) { Remove-Item -Recurse -Force $Inst; Row removed $Inst }
        Remove-FromUserPath $BinDir
        if ((Test-Path $Prefix) -and -not (Get-ChildItem -Force $Prefix)) { Remove-Item $Prefix }
        if (-not $had) { Write-Host "Nothing to remove: no Tenzro install found under $Prefix." }
        if (Test-Path $Prefix) { Write-Host "Left in place: $Prefix (settings and any node data). Delete it yourself if you want it gone." }
        return
    }

    # ---- this machine
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { Fail 'this is not Windows' 'install.ps1 is for Windows' 'on Linux or macOS run: curl -fsSL https://downloads.tenzro.com/install.sh | sh' }
    if ($arch -ne 'AMD64') { Fail "unsupported CPU: $arch" 'Tenzro publishes a Windows x86_64 build only' 'use an x86_64 Windows machine, or build from source (README, Build from Source)' }
    $gpu = 'none'
    try {
        $names = (Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object { $_.Name }) -join ', '
        if ($names -match 'NVIDIA') { $gpu = 'nvidia' }
    } catch {}

    Write-Host ''
    Write-Host 'Installing Tenzro'
    Write-Host ''
    Row machine ("windows x86_64, " + $(if ($gpu -eq 'nvidia') { 'NVIDIA GPU' } else { 'no NVIDIA GPU' }))

    # ---- fetch
    $work = Join-Path ([IO.Path]::GetTempPath()) ('tenzro-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        function Fetch($name, $dest) {
            if ($From) {
                $src = Join-Path $From $name
                if (-not (Test-Path $src)) { Fail "$src is missing" '-From needs the archive, SHA256SUMS and SHA256SUMS.sig in one folder' "download them from $BaseUrl and try again" }
                Copy-Item $src $dest; return
            }
            try { Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$name" -OutFile $dest }
            catch {
                $why = $_.Exception.Message
                if ($why -match 'remote name|No such host|could not be resolved|NameResolution') { $why = "the name $(([Uri]$BaseUrl).Host) could not be looked up, so this machine has no working DNS or no internet" }
                elseif ($why -match '404') { $why = "the server has no file $name" }
                elseif ($why -match 'timed out') { $why = "the connection to $BaseUrl timed out" }
                elseif ($why -match 'SSL|TLS|certificate|trust') { $why = "the TLS connection to $BaseUrl could not be verified" }
                Fail "could not download $name" $why 'check your connection and run this again. Offline: download the archive, SHA256SUMS and SHA256SUMS.sig on another machine and use -From <folder>'
            }
        }
        $sums = Join-Path $work 'SHA256SUMS'; $sigf = Join-Path $work 'SHA256SUMS.sig'
        Fetch 'SHA256SUMS' $sums
        Fetch 'SHA256SUMS.sig' $sigf

        # ---- verify the signature with .NET ECDsa (P-256, SHA-256, DER signature from cosign/openssl)
        $b64 = ($PubKey -split "`n" | Where-Object { $_ -notmatch '-----' }) -join ''
        $spki = [Convert]::FromBase64String($b64.Trim())
        $fpr = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($spki)) -replace '-', '').ToLower()
        if ($fpr -ne $KeyFpr) { Fail 'the release key inside this script is not the published one' "its fingerprint is $fpr, expected $KeyFpr" 'download install.ps1 again from https://downloads.tenzro.com/install.ps1; if that does not help, stop and ask' }
        function Read-DerSignature([byte[]]$der) {
            # SEQUENCE { INTEGER r, INTEGER s } -> 64 bytes r||s
            $i = 0
            if ($der[$i++] -ne 0x30) { throw 'bad signature' }
            $l = $der[$i++]; if ($l -band 0x80) { $i += ($l -band 0x7f) }
            $out = New-Object byte[] 64
            foreach ($part in 0, 1) {
                if ($der[$i++] -ne 0x02) { throw 'bad signature' }
                $n = $der[$i++]
                $v = $der[$i..($i + $n - 1)]; $i += $n
                while ($v.Length -gt 32 -and $v[0] -eq 0) { $v = $v[1..($v.Length - 1)] }
                if ($v.Length -gt 32) { throw 'bad signature' }
                [Array]::Copy([byte[]]$v, 0, $out, ($part * 32) + (32 - $v.Length), $v.Length)
            }
            return , $out
        }
        $verified = $false
        try {
            $sigtext = ([IO.File]::ReadAllText($sigf)).Trim()
            $rs = Read-DerSignature ([Convert]::FromBase64String($sigtext))
            # ECParameters and ECPoint are structs: build the point first, then assign it whole.
            $pt = New-Object Security.Cryptography.ECPoint
            $pt.X = [byte[]]$spki[($spki.Length - 64)..($spki.Length - 33)]
            $pt.Y = [byte[]]$spki[($spki.Length - 32)..($spki.Length - 1)]
            $q = New-Object Security.Cryptography.ECParameters
            $q.Curve = [Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
            $q.Q = $pt
            $ec = [Security.Cryptography.ECDsa]::Create($q)
            $hash = [Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($sums))
            $verified = $ec.VerifyHash($hash, $rs)
        } catch { $verified = $false }
        if (-not $verified) { Fail 'the signature on SHA256SUMS does not verify' 'the list of release hashes was not signed by the Tenzro release key (damaged download, or something is altering it in transit)' 'do not install from this source. Try again from another network, or follow docs/VERIFY-DOWNLOAD.md' }
        Row signature ('verified, release key ' + $KeyFpr.Substring(0, 8))

        # ---- pick the archive
        $listed = @{}
        Get-Content $sums | Where-Object { $_.Trim() } | ForEach-Object { $p = $_ -split '\s+', 2; $listed[$p[1].TrimStart('*').Trim()] = $p[0].ToLower() }
        if ($Target) { $name = $Target -replace '\.zip$', '' }
        else {
            $name = $null
            foreach ($f in 'cuda', 'cpu') { if ($listed.ContainsKey("tenzro-node-windows-x86_64-$f.zip") -and (($f -eq 'cuda' -and $gpu -eq 'nvidia') -or $f -eq 'cpu')) { $name = "tenzro-node-windows-x86_64-$f"; break } }
            if (-not $name -and $listed.ContainsKey('tenzro-node-windows-x86_64-cuda.zip')) { $name = 'tenzro-node-windows-x86_64-cuda'; Write-Host "  note: this release's Windows build is the NVIDIA CUDA build and no NVIDIA GPU was found; the CLI is installed, GPU features will not work." }
            if (-not $name) { Fail 'this release has no Windows build' ('the signed list holds: ' + ($listed.Keys -join ' ')) 'build from source (README, Build from Source)' }
        }
        if (-not $listed.ContainsKey("$name.zip")) { Fail "$name is not in this release" ('the signed list holds: ' + ($listed.Keys -join ' ')) 'pick one of those with -Target' }
        $want = $listed["$name.zip"]
        $short = $want.Substring(0, 12)
        Row build $name
        $vdir = Join-Path (Join-Path $Inst 'versions') "$name-$short"

        if ($DryRun) {
            Row install "would go to $vdir and add $BinDir to your PATH"
            Write-Host ''; Write-Host 'Dry run: the signed list verified; the archive was not downloaded and nothing was changed.'; Write-Host ''
            return
        }

        # ---- the archive
        if (Test-Path (Join-Path $vdir 'bin')) { Row archive 'already installed, nothing to download' }
        else {
            Write-Host "  ${dim}downloading $name.zip${off}"
            $zip = Join-Path $work 'a.zip'
            Fetch "$name.zip" $zip
            $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
            if ($got -ne $want) { Fail 'the archive does not match the signed list' "$name.zip hashes to $got; the signed SHA256SUMS lists $want (truncated or altered download)" 'the file was discarded. Run this again; if it repeats, stop and ask' }
            Row checksum "verified, sha256 $short"
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $za = [IO.Compression.ZipFile]::OpenRead($zip)
            try { foreach ($e in $za.Entries) { if ($e.FullName -match '(^|[\\/])\.\.([\\/]|$)' -or [IO.Path]::IsPathRooted($e.FullName)) { Fail 'the archive has unsafe paths' 'an entry would be written outside the install folder' 'do not use it; stop and ask' } } } finally { $za.Dispose() }
            $x = Join-Path $work 'x'
            [IO.Compression.ZipFile]::ExtractToDirectory($zip, $x)
            Remove-Item $zip -Force
            $root = Join-Path $x $name
            if (-not (Test-Path (Join-Path $root 'bin\tenzro.exe')) -or -not (Test-Path (Join-Path $root 'bin\tenzro-node.exe'))) { Fail 'the archive does not contain bin\tenzro.exe and bin\tenzro-node.exe' 'unexpected layout' 'stop and ask' }
            $cli = Join-Path $root 'bin\tenzro.exe'; $node = Join-Path $root 'bin\tenzro-node.exe'
            $ver = ''
            try { $ver = ((& $cli --version 2>&1 | Select-Object -First 1) -as [string]).Trim() } catch {}
            if (-not $ver -or $LASTEXITCODE -ne 0) { Fail 'the downloaded binary does not run on this machine' "tenzro.exe --version said: $ver" 'install the Microsoft Visual C++ Redistributable (x64) and run this again; if it repeats, stop and ask' }
            $cliv = ($ver -split '\s+')[-1]
            if ($Version -and $cliv -ne $Version) { Fail "this release is version $cliv, you asked for $Version" 'downloads.tenzro.com serves the current release only' 'install without -Version, or fetch the archive of that version yourself and use -From' }
            $hw = ''
            try { $hw = (& $node hardware 2>$null) -join "`n" } catch {}
            if ($hw -match 'startup: ok') { Row self-check ('build ' + ([regex]::Match($hw, 'build: (\S+)').Groups[1].Value) + ', ' + ([regex]::Match($hw, 'gpus: (\d+)').Groups[1].Value) + ' GPU(s), startup ok') }
            else { Write-Host "  note: the hardware self-check did not finish ($($hw -replace "`n", ' ')); the CLI is installed anyway." }
            New-Item -ItemType Directory -Force -Path (Join-Path $Inst 'versions') | Out-Null
            Move-Item $root $vdir
            Row install $vdir
        }
        $cliv = if ($cliv) { $cliv } else { ((& (Join-Path $vdir 'bin\tenzro.exe') --version) -split '\s+')[-1] }

        # ---- current (a junction: no administrator rights needed) and PATH
        if (Test-Path $Current) { cmd /c rmdir "$Current" | Out-Null }
        New-Item -ItemType Junction -Path $Current -Target $vdir | Out-Null
        Row linked "$Current -> $vdir"
        Get-ChildItem (Join-Path $Inst 'versions') -Directory | Sort-Object LastWriteTime -Descending | Select-Object -Skip 2 | Where-Object { $_.FullName -ne $vdir } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        $up = Get-UserPath
        $onPath = $up -and (($up -split ';') | Where-Object { $_.TrimEnd('\') -eq $BinDir.TrimEnd('\') })
        $session = $true
        if (-not $onPath) {
            $do = $false
            if ($ModifyPath) { $do = $true }
            elseif (-not $NoModifyPath -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
                $a = Read-Host "  $BinDir is not on your PATH. Add it for your user? [Y/n]"
                if ($a -eq '' -or $a -match '^(y|yes)$') { $do = $true }
            }
            if ($do) { [Environment]::SetEnvironmentVariable('Path', ($(if ($up) { "$up;" } else { '' }) + $BinDir), 'User'); Row path 'added to your user PATH' }
            else { Row path "$BinDir is not on your PATH" }
        }
        if (-not (($env:Path -split ';') -contains $BinDir)) { $env:Path = "$BinDir;$env:Path" }   # this session only

        $secs = [int]((Get-Date) - $t0).TotalSeconds
        Write-Host ''
        Write-Host "Tenzro $cliv is installed (${secs}s)"
        Write-Host ''
        Write-Host 'Open a terminal and run:'
        Write-Host ''
        Write-Host "    ${acc}tenzro${off}"
        Write-Host ''
        Write-Host "${dim}The first time, it takes you through setup; after that it opens the console. `tenzro --help` lists everything.${off}"
        Write-Host "${dim}Update: run this installer again. Remove: -Uninstall${off}"
        Write-Host ''
    } finally {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}

try { Install-Tenzro; $global:LASTEXITCODE = 0 }
catch { [Console]::Error.WriteLine($_.Exception.Message); $global:LASTEXITCODE = 1 }
