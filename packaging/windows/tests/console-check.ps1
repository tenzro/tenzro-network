<#
Tests the web console check of build-msi.ps1 (the block between its "console check" markers),
without an archive or WiX. Run: powershell -NoProfile -ExecutionPolicy Bypass -File console-check.ps1
#>
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw (Join-Path $PSScriptRoot '..\build-msi.ps1')
$block = [regex]::Match($src, '(?s)# console check begin(.*)# console check end').Groups[1].Value
if (-not $block) { throw 'no console check block in build-msi.ps1' }
. ([scriptblock]::Create($block))
$pass = 0; $fail = 0
function Case([string]$name, [string[]]$console, [string[]]$consoleSrc, [string]$want) {
    $got = ''
    try { Assert-Console $console $consoleSrc } catch { $got = $_.Exception.Message }
    if (($want -eq '' -and $got -eq '') -or ($want -ne '' -and $got -like "*$want*")) { $script:pass++; "PASS $name" }
    else { $script:fail++; "FAIL ${name}: got '$got'" }
}
Case 'a complete console is accepted' @('share\console\index.html', 'share\console\sw.js') @('share\console\src\app.js') ''
Case 'no index.html is refused' @('share\console\sw.js') @('share\console\src\app.js') 'no web console (share\console\index.html)'
Case 'no console at all is refused' @() @() 'no web console'
Case 'no scripts are refused' @('share\console\index.html') @() 'no web console scripts'
"$pass passed, $fail failed"
exit $fail
