# php2shell-check.ps1 - read-only check for PHP2Shell (CVE-2026-109618, CVE-2026-109619) on Windows.
# STATUS: UNTESTED. Written alongside php2shell-check.sh but never run (no PowerShell in the lab). Read it before use.
#
# MIT License
# Copyright (c) 2026 Brandefense
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright
# notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
#
# Evidence: runtime (php-cgi.exe / php.exe / Apache php*apache*.dll that really serve HTTP), process (running PHP
# processes started BEFORE the binary/DLL on disk was last written = old code still serving), deployment (docker images
# and containers). No network, no writes. Exit codes: 0 PASS, 1 WARN, 2 FAIL, 3 nothing found.
# Fixed upstream: 8.2.35, 8.3.36, 8.4.27, 8.5.12. 8.1 and older: no upstream fix.
param([switch]$NoContainers)
$ErrorActionPreference = 'SilentlyContinue'
$script:p = 0; $script:w = 0; $script:f = 0; $script:found = $false
function Emit($lvl, $sec, $msg) {
  switch ($lvl) { 'PASS' { $script:p++ } 'WARN' { $script:w++ } 'FAIL' { $script:f++ } }
  $col = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$lvl]
  Write-Host ("[{0}] {1,-10} {2}" -f $lvl, $sec, $msg) -ForegroundColor $col
}
function FixedState([string]$v) {
  if ($v -notmatch '^(\d+)\.(\d+)\.(\d+)') { return 'unknown' }
  $ma = [int]$Matches[1]; $mi = [int]$Matches[2]; $pa = [int]$Matches[3]
  if ($ma -gt 8) { return 'fixed' }; if ($ma -lt 8) { return 'vulnerable' }
  switch ($mi) { 0 { 'vulnerable' } 1 { 'vulnerable' } 2 { if ($pa -ge 35) { 'fixed' } else { 'vulnerable' } }
    3 { if ($pa -ge 36) { 'fixed' } else { 'vulnerable' } } 4 { if ($pa -ge 27) { 'fixed' } else { 'vulnerable' } }
    5 { if ($pa -ge 12) { 'fixed' } else { 'vulnerable' } } default { 'fixed' } }
}
function BinVersion([string]$exe) {
  $o = & $exe -v 2>$null | Select-Object -First 1
  if ($o -match 'PHP (\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}
Write-Host '== 2. runtime and 3. process evidence'
$procs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(php-cgi|php|php-win|httpd|php-fpm)\.exe$' }
$seen = @{}
foreach ($pr in $procs) {
  $script:found = $true
  $exe = $pr.ExecutablePath; if (-not $exe) { continue }
  $start = $pr.CreationDate
  $isPhp = $pr.Name -match '^php'
  $ver = $null
  if ($isPhp) { $ver = BinVersion $exe }
  else {  # Apache: look for the PHP module DLL next to the configuration
    $dll = Get-ChildItem -Path (Split-Path (Split-Path $exe)) -Recurse -Filter 'php*apache2_4.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dll) { $exe = $dll.FullName; $ver = (Get-Item $exe).VersionInfo.ProductVersion }
  }
  if (-not $ver) { Emit 'WARN' 'runtime' "$($pr.Name) pid $($pr.ProcessId): version not readable ($exe)"; continue }
  $key = "$exe|$ver"
  if (-not $seen.ContainsKey($key)) {
    $seen[$key] = 1
    if ((FixedState $ver) -eq 'fixed') { Emit 'PASS' 'runtime' "$exe = $ver (>= fixed release)" }
    else { Emit 'FAIL' 'runtime' "$exe = $ver is below the fixed release (no backport channel on Windows builds)" }
  }
  $written = (Get-Item $exe).LastWriteTime
  if ($start -lt $written) {
    Emit 'FAIL' 'process' "pid $($pr.ProcessId) started $start BEFORE $exe was last written $written : restart the service, the old code may still be serving"
  }
}
if (-not $procs) { Emit 'INFO' 'runtime' 'no running php/php-cgi/httpd process found' }
Write-Host '== 4. deployment evidence'
if ($NoContainers) { Emit 'INFO' 'deployment' 'skipped (-NoContainers)' }
elseif (Get-Command docker -ErrorAction SilentlyContinue) {
  foreach ($c in (docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}')) {
    $id, $img, $name = $c -split '\|'
    $o = docker exec $id php -v 2>$null | Select-Object -First 1
    if ($o -match 'PHP (\d+\.\d+\.\d+)') {
      $script:found = $true
      if ((FixedState $Matches[1]) -eq 'fixed') { Emit 'PASS' 'deployment' "container $name ($img) runs PHP $($Matches[1])" }
      else { Emit 'FAIL' 'deployment' "container $name ($img) runs PHP $($Matches[1]) (below fixed release): rebuild and redeploy" }
    }
  }
} else { Emit 'INFO' 'deployment' 'no docker CLI here' }
Write-Host '== ini values (informational): run `php -i | findstr /i "upload_progress memory_limit post_max_size fatal_error_backtraces"` for each PHP above'
Write-Host ("== summary: {0} PASS, {1} WARN, {2} FAIL" -f $script:p, $script:w, $script:f)
if (-not $script:found) { Write-Host 'nothing PHP-related found'; exit 3 }
if ($script:f -gt 0) { Write-Host 'RESULT: FAIL'; exit 2 }
if ($script:w -gt 0) { Write-Host 'RESULT: WARN'; exit 1 }
Write-Host 'RESULT: PASS'; exit 0
