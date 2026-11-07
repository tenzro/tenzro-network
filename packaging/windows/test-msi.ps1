<#
.SYNOPSIS
  Install, upgrade and uninstall tests for the Tenzro MSI (runs on Windows, elevated).

.DESCRIPTION
  Installs only into a test folder, snapshots the machine and user PATH
  first and verifies at the end that both are byte for byte what they were.
  Pass -UpgradeMsi (a build with a higher version) to test upgrade in place.

  Usage: test-msi.ps1 -Msi <path> [-UpgradeMsi <path>] [-InstallDir C:\tmp\tz-msi-test\]
#>
param(
    [Parameter(Mandatory)][string]$Msi,
    [string]$UpgradeMsi = '',
    [string]$InstallDir = 'C:\tmp\tz-msi-test\',
    [string]$LogDir = '',
    [string]$Version = '0.2.1'
)

$ErrorActionPreference = 'Stop'
if (-not $InstallDir.EndsWith('\')) { $InstallDir += '\' }
if (-not $LogDir) { $LogDir = Join-Path ([IO.Path]::GetTempPath()) ('tz-msi-logs-' + [Guid]::NewGuid().ToString('N')) }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$script:fail = 0
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    if ($ok) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name  $detail"; $script:fail++ }
}
function Section([string]$t) { Write-Host ''; Write-Host "== $t" }

$MKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
function Get-PathRaw([string]$scope) {
    $k = if ($scope -eq 'machine') { [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($MKey) } else { [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment') }
    try {
        $v = $k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = try { $k.GetValueKind('Path').ToString() } catch { 'none' }
        return @{ Value = [string]$v; Kind = $kind }
    } finally { $k.Close() }
}
function Count-Entry([string]$scope, [string]$dir) {
    $v = (Get-PathRaw $scope).Value
    return @($v -split ';' | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') }).Count
}
function Msi-Prop([string]$msi, [string]$prop) {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($msi, 0))
    $v = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property='$prop'"))
    $v.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $v, $null) | Out-Null
    $r = $v.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $v, $null)
    if ($r) { return $r.GetType().InvokeMember('StringData', 'GetProperty', $null, $r, @(1)) }
    return $null
}
function Run-Msi([string]$tag, [string]$argsText) {
    $log = Join-Path $LogDir "$tag.log"
    $p = Start-Process msiexec.exe -ArgumentList "$argsText /qn /l*v `"$log`"" -Wait -PassThru
    return $p.ExitCode
}
# Run a command line in a new process whose environment is built from the
# registry PATH values (what a newly opened terminal would see).
function Run-Fresh([string]$cmdline, [hashtable]$extraEnv = @{}) {
    $m = [Environment]::ExpandEnvironmentVariables((Get-PathRaw 'machine').Value)
    $u = [Environment]::ExpandEnvironmentVariables((Get-PathRaw 'user').Value)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\cmd.exe"
    $psi.Arguments = "/c $cmdline"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['Path'] = "$m;$u"
    foreach ($k in $extraEnv.Keys) { $psi.EnvironmentVariables[$k] = $extraEnv[$k] }
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    return @{ Rc = $p.ExitCode; Out = ($o.Result + $e.Result).TrimEnd() }
}
function Tenzro-Services {
    @(Get-Service | Where-Object { $_.Name -like '*tenzro*' -or $_.DisplayName -like '*tenzro*' })
}
function Tenzro-Procs {
    @(Get-Process | Where-Object { $_.ProcessName -like 'tenzro*' -and $_.Path -like "$InstallDir*" })
}
function ArpEntries {
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    @(Get-ChildItem $base | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -eq 'Tenzro' })
}
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Tenzro'

function Verify-Installed([string]$mode, [string]$version) {
    $bin = Join-Path $InstallDir 'bin'
    foreach ($f in 'bin\tenzro.exe', 'bin\tenzro-node.exe', 'bin\tenzro-check.cmd', 'LICENSE.txt', 'NOTICE.txt', 'PROVENANCE.txt', 'tenzro-check.ps1', 'tenzro-terminal.cmd') {
        Check "file present: $f" (Test-Path -LiteralPath (Join-Path $InstallDir $f))
    }
    $arp = @(ArpEntries)
    Check 'one Add/Remove Programs entry named Tenzro' ($arp.Count -eq 1) "count=$($arp.Count)"
    if ($arp.Count -ge 1) {
        Check "ARP publisher is Tenzro" ($arp[0].Publisher -eq 'Tenzro') $arp[0].Publisher
        Check "ARP version is $version" ($arp[0].DisplayVersion -eq $version) $arp[0].DisplayVersion
    }
    foreach ($s in 'Tenzro.lnk', 'Tenzro setup.lnk', 'Tenzro hardware check.lnk', 'Uninstall Tenzro.lnk') {
        Check "shortcut: $s" (Test-Path -LiteralPath (Join-Path $startMenu $s))
    }
    $sys = Count-Entry 'machine' $bin; $usr = Count-Entry 'user' $bin
    switch ($mode) {
        'system' { Check 'PATH: system has exactly one entry, user has none' ($sys -eq 1 -and $usr -eq 0) "sys=$sys usr=$usr" }
        'user'   { Check 'PATH: user has exactly one entry, system has none' ($usr -eq 1 -and $sys -eq 0) "sys=$sys usr=$usr" }
        'none'   { Check 'PATH: unchanged (no entry in either)' ($usr -eq 0 -and $sys -eq 0) "sys=$sys usr=$usr" }
    }
    Check 'no Tenzro service exists' (@(Tenzro-Services).Count -eq 0)
    Check 'no Tenzro process running from the install folder' (@(Tenzro-Procs).Count -eq 0)
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Tenzro\Installer' -ErrorAction SilentlyContinue
    Check "registry: AddToPath=$mode, Version=$version" ($reg -and $reg.AddToPath -eq $mode -and $reg.Version -eq $version) ($reg | Out-String)
}
function Verify-Removed([string]$what) {
    $bin = Join-Path $InstallDir 'bin'
    Check "$what`: install folder gone" (-not (Test-Path -LiteralPath $InstallDir)) (@(Get-ChildItem -Recurse -ErrorAction SilentlyContinue $InstallDir).Count.ToString() + ' items left')
    Check "$what`: Start menu folder gone" (-not (Test-Path -LiteralPath $startMenu))
    Check "$what`: ARP entry gone" (@(ArpEntries).Count -eq 0)
    Check "$what`: registry key HKLM\SOFTWARE\Tenzro\Installer gone" (-not (Test-Path 'HKLM:\SOFTWARE\Tenzro\Installer'))
    Check "$what`: no PATH entry left (system or user)" ((Count-Entry 'machine' $bin) -eq 0 -and (Count-Entry 'user' $bin) -eq 0)
    Check "$what`: no Tenzro service" (@(Tenzro-Services).Count -eq 0)
}

# ---------------------------------------------------------------- snapshot
$snapM = Get-PathRaw 'machine'; $snapU = Get-PathRaw 'user'
Write-Host "Snapshot: machine PATH $($snapM.Value.Length) chars ($($snapM.Kind)), user PATH $($snapU.Value.Length) chars ($($snapU.Kind))"
Write-Host "machine PATH tail: $(($snapM.Value -split ';' | Select-Object -Last 2) -join ' ; ')"
Write-Host "user PATH tail:    $(($snapU.Value -split ';' | Select-Object -Last 2) -join ' ; ')"
$ver = Msi-Prop $Msi 'ProductVersion'
$pc = Msi-Prop $Msi 'ProductCode'
Write-Host "MSI under test: version $ver, ProductCode $pc"
Check 'test folder does not exist before the run' (-not (Test-Path -LiteralPath $InstallDir))
Check 'no Tenzro installed before the run' (@(ArpEntries).Count -eq 0)

try {
    # ------------------------------------------------------------ system
    Section 'Install, ADDTOPATH=system'
    $rc = Run-Msi 'sys-install' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" ADDTOPATH=system"
    Check 'msiexec exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Installed 'system' $ver
    $after = Get-PathRaw 'machine'
    Write-Host "machine PATH kind after install: $($after.Kind); tail: $(($after.Value -split ';' | Select-Object -Last 2) -join ' ; ')"
    Check 'machine PATH differs from the snapshot only by the appended entry' ($after.Value -eq ($snapM.Value + ';' + $InstallDir + 'bin')) $after.Value.Substring([Math]::Max(0, $after.Value.Length - 80))
    Check 'machine PATH value kind unchanged' ($after.Kind -eq $snapM.Kind) "$($snapM.Kind) -> $($after.Kind)"

    Section 'New terminal sees tenzro (PATH rebuilt from the registry)'
    $r = Run-Fresh 'where tenzro'
    Write-Host "where tenzro -> $($r.Out)"
    Check 'where tenzro resolves to the install folder' ($r.Rc -eq 0 -and $r.Out -like "$InstallDir*")
    $r = Run-Fresh 'tenzro --version'
    Write-Host "tenzro --version -> $($r.Out)"
    Check "tenzro --version prints tenzro $Version" ($r.Rc -eq 0 -and $r.Out -match ('^tenzro ' + [regex]::Escape($Version)))
    $r = Run-Fresh 'tenzro setup --help'
    Write-Host "tenzro setup --help (first lines):"; ($r.Out -split "`r?`n" | Select-Object -First 6) | ForEach-Object { Write-Host "  $_" }
    Check 'tenzro setup --help exits 0' ($r.Rc -eq 0)

    Section 'Hardware check (this machine)'
    function Profile-Tenzro { @(Get-ChildItem -Force -ErrorAction SilentlyContinue $env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA | Where-Object { $_.Name -like '*tenzro*' } | ForEach-Object { $_.FullName }) | Sort-Object }
    $profBefore = (Profile-Tenzro) -join '|'
    $r = Run-Fresh 'tenzro-check'
    Write-Host "tenzro-check (exit $($r.Rc)):"; ($r.Out -split "`r?`n") | ForEach-Object { Write-Host "  $_" }
    Check 'tenzro-check exits 0 and starts with OK' ($r.Rc -eq 0 -and $r.Out -match '^\s*OK:')
    $r = Run-Fresh 'tenzro-check' @{ CUDA_VISIBLE_DEVICES = '-1' }
    Write-Host "tenzro-check with CUDA_VISIBLE_DEVICES=-1 (simulated no GPU) (exit $($r.Rc)):"; ($r.Out -split "`r?`n") | ForEach-Object { Write-Host "  $_" }
    Check 'simulated no-GPU: exit 1 and NOT READY text' ($r.Rc -eq 1 -and $r.Out -match 'NOT READY')
    Check 'check created nothing named tenzro in the user profile, AppData or LocalAppData' (((Profile-Tenzro) -join '|') -eq $profBefore)
    $leftTemp = @(Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter 'tenzro-check-*' -ErrorAction SilentlyContinue)
    Check 'check removed its throw-away data dir' ($leftTemp.Count -eq 0) "$($leftTemp.Count) left"

    Section 'Terminal launcher (non-interactive parts)'
    $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $startMenu 'Tenzro.lnk'))
    Write-Host "Tenzro.lnk -> $($lnk.TargetPath) $($lnk.Arguments)  workdir=$($lnk.WorkingDirectory)"
    Check 'Tenzro.lnk targets cmd.exe with the launcher' ($lnk.TargetPath -ieq "$env:SystemRoot\System32\cmd.exe" -and $lnk.Arguments -like "*$($InstallDir)tenzro-terminal.cmd*menu*")

    Section 'Uninstall by ProductCode'
    $rc = Run-Msi 'sys-uninstall' "/x $pc"
    Check 'msiexec exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Removed 'after uninstall'
    $a = Get-PathRaw 'machine'; $b = Get-PathRaw 'user'
    Check 'machine PATH identical to the snapshot' ($a.Value -eq $snapM.Value -and $a.Kind -eq $snapM.Kind)
    Check 'user PATH identical to the snapshot' ($b.Value -eq $snapU.Value -and $b.Kind -eq $snapU.Kind)

    # ------------------------------------------------------------ user
    Section 'Install, ADDTOPATH=user'
    $rc = Run-Msi 'usr-install' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" ADDTOPATH=user"
    Check 'msiexec exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Installed 'user' $ver
    $a = Get-PathRaw 'machine'
    Check 'machine PATH untouched' ($a.Value -eq $snapM.Value)
    $r = Run-Fresh 'tenzro --version'
    Check 'new terminal: tenzro --version works via user PATH' ($r.Rc -eq 0 -and $r.Out -match ('^tenzro ' + [regex]::Escape($Version))) $r.Out
    $rc = Run-Msi 'usr-uninstall' "/x `"$Msi`""
    Check 'uninstall by package path: exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Removed 'user mode uninstall'
    $b = Get-PathRaw 'user'
    Check 'user PATH identical to the snapshot' ($b.Value -eq $snapU.Value -and $b.Kind -eq $snapU.Kind)

    # ------------------------------------------------------------ none
    Section 'Install, ADDTOPATH=none'
    $rc = Run-Msi 'none-install' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" ADDTOPATH=none"
    Check 'msiexec exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Installed 'none' $ver
    $r = Run-Fresh 'where tenzro'
    Check 'new terminal: tenzro is not on PATH' ($r.Rc -ne 0)
    $rc = Run-Msi 'none-uninstall' "/x $pc"
    Verify-Removed 'none mode uninstall'

    # ------------------------------------------------------------ default + invalid
    Section 'Install with no ADDTOPATH (documented default: system)'
    $rc = Run-Msi 'def-install' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`""
    Check 'msiexec exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Installed 'system' $ver
    Section 'Reinstall over the same version (repair-style install)'
    $rc = Run-Msi 'reinstall' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" REINSTALL=ALL REINSTALLMODE=vomus"
    Check 'reinstall exit code 0' ($rc -eq 0) "rc=$rc"
    Check 'still exactly one PATH entry' ((Count-Entry 'machine' (Join-Path $InstallDir 'bin')) -eq 1)
    $rc = Run-Msi 'def-uninstall' "/x $pc"
    Verify-Removed 'default-mode uninstall'

    Section 'Invalid ADDTOPATH is rejected'
    $rc = Run-Msi 'bad-install' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" ADDTOPATH=bogus"
    Check 'msiexec refuses (exit 1603)' ($rc -eq 1603) "rc=$rc"
    Check 'nothing installed' (@(ArpEntries).Count -eq 0 -and -not (Test-Path -LiteralPath $InstallDir))

    # ------------------------------------------------------------ fresh install after removal
    Section 'Install again after a full removal'
    $rc = Run-Msi 'again-install' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" ADDTOPATH=system"
    Check 'msiexec exit code 0' ($rc -eq 0) "rc=$rc"
    Verify-Installed 'system' $ver
    $rc = Run-Msi 'again-uninstall' "/x $pc"
    Verify-Removed 'second uninstall'

    # ------------------------------------------------------------ upgrade
    if ($UpgradeMsi) {
        $ver2 = Msi-Prop $UpgradeMsi 'ProductVersion'; $pc2 = Msi-Prop $UpgradeMsi 'ProductCode'
        Section "Upgrade in place: $ver (user PATH) -> $ver2 (no properties given)"
        Write-Host "new ProductCode $pc2"
        Check 'upgrade package has a different ProductCode and the same UpgradeCode' (($pc2 -ne $pc) -and ((Msi-Prop $UpgradeMsi 'UpgradeCode') -eq (Msi-Prop $Msi 'UpgradeCode')))
        $rc = Run-Msi 'up-old' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`" ADDTOPATH=user"
        Check 'old version installed' ($rc -eq 0) "rc=$rc"
        $rc = Run-Msi 'up-new' "/i `"$UpgradeMsi`" INSTALLFOLDER=`"$InstallDir`""
        Check 'upgrade exit code 0' ($rc -eq 0) "rc=$rc"
        Verify-Installed 'user' $ver2
        $arp = @(ArpEntries)
        Check 'old product code is gone, new one present' (($arp.Count -eq 1) -and ($arp[0].PSChildName -eq $pc2)) ($arp | Out-String)
        $rc = Run-Msi 'up-down' "/i `"$Msi`" INSTALLFOLDER=`"$InstallDir`""
        Check 'installing the older version over the newer is refused (1638 or 1603)' ($rc -eq 1638 -or $rc -eq 1603) "rc=$rc"
        $rc = Run-Msi 'up-uninstall' "/x $pc2"
        Verify-Removed 'after upgrade then uninstall'
    }
}
finally {
    # best-effort cleanup if a step threw midway
    foreach ($code in @($pc, $pc2)) { if ($code -and (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$code")) { Start-Process msiexec.exe -ArgumentList "/x $code /qn" -Wait } }
    if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Section 'Final state'
$a = Get-PathRaw 'machine'; $b = Get-PathRaw 'user'
Check 'machine PATH identical to the start-of-run snapshot' ($a.Value -eq $snapM.Value -and $a.Kind -eq $snapM.Kind)
Check 'user PATH identical to the start-of-run snapshot' ($b.Value -eq $snapU.Value -and $b.Kind -eq $snapU.Kind)
Check 'test folder removed' (-not (Test-Path -LiteralPath $InstallDir))
Write-Host "Logs: $LogDir"
Write-Host ''
if ($script:fail -eq 0) { Write-Host 'RESULT: all checks passed'; exit 0 } else { Write-Host "RESULT: $($script:fail) check(s) FAILED"; exit 1 }
