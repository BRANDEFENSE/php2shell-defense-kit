<# Read-only local metadata inventory. Does not execute PHP binaries or collect command lines, environment, sessions or credentials.
   Static config occurrences are not effective configuration. Tested by review only; Windows execution is not validated in this release. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Output,
    [string[]]$ConfigRoot = @('C:\PHP', 'C:\Program Files\PHP', 'C:\inetpub'),
    [int]$MaxFiles = 10000
)
$ErrorActionPreference = 'Stop'
$gaps = [System.Collections.Generic.List[object]]::new()
$processes = @()
$services = @()
$binaries = @()
$configs = [System.Collections.Generic.List[object]]::new()
$allowed = @('session.upload_progress.enabled','session.upload_progress.name','session.serialize_handler','session.use_strict_mode','memory_limit','post_max_size','upload_max_filesize','max_file_uploads','max_input_vars','max_input_nesting_level','max_execution_time','fatal_error_backtraces','display_errors','log_errors','error_reporting','expose_php')
try {
    $processes = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(php(-cgi)?|httpd|w3wp|frankenphp)\.exe$' } | ForEach-Object {
        [pscustomobject]@{ pid=$_.ProcessId; parent_pid=$_.ParentProcessId; name=$_.Name; executable=$_.ExecutablePath; running_version='unknown' }
    })
} catch { $gaps.Add(@{component='processes'; reason='unavailable_or_permission_denied'}) }
try {
    $services = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'php|apache|w3svc|frankenphp' -or $_.PathName -match 'php|httpd|frankenphp' } | Select-Object Name,State,StartMode)
} catch { $gaps.Add(@{component='services'; reason='unavailable_or_permission_denied'}) }
$count = 0
foreach ($root in $ConfigRoot) {
    if (!(Test-Path -LiteralPath $root)) { $gaps.Add(@{path=$root; reason='missing_root'}); continue }
    try {
        # Get-ChildItem does not follow directory symlinks unless FollowSymlink is explicitly requested.
        $files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction Stop | Where-Object { !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and ($_.Name -match '^(php.*\.exe|php\.ini|\.user\.ini|\.htaccess|web\.config)$' -or $_.Extension -eq '.conf') } | Select-Object -First ($MaxFiles + 1)
        foreach ($file in $files) {
            $count++
            if ($count -gt $MaxFiles) { $gaps.Add(@{path=$root; reason='file_limit_reached'}); break }
            if ($file.Extension -eq '.exe') {
                $binaries += [pscustomobject]@{path=$file.FullName; file_version=$file.VersionInfo.FileVersion; product_version=$file.VersionInfo.ProductVersion; scope='on_disk_metadata_not_running_web_build'; vendor_patch_status='unknown'}
                continue
            }
            if ($file.Length -gt 1MB) { $gaps.Add(@{path=$file.FullName; reason='oversized_file_skipped'}); continue }
            $number=0
            foreach ($line in [IO.File]::ReadLines($file.FullName)) {
                $number++
                if ($line -match '^\s*[;#]') { continue }
                foreach ($key in $allowed) {
                    $pattern = '(?<![\w.])' + [regex]::Escape($key) + '\s*=\s*([A-Za-z0-9_.+/-]+)'
                    if ($line -match $pattern) {
                        $configs.Add([pscustomobject]@{path=$file.FullName; line=$number; setting=$key; value=$Matches[1]; evidence='static_occurrence_not_effective_runtime'})
                    }
                }
            }
        }
    } catch { $gaps.Add(@{path=$root; reason='config_tree_partial_or_unreadable'}) }
}
$report = [ordered]@{
    schema_version='1.0-windows'; observed_at=[DateTime]::UtcNow.ToString('o'); host=$env:COMPUTERNAME
    processes=$processes; services=$services; binaries=$binaries; configurations=$configs; coverage_gaps=@($gaps.ToArray())
    limitations=@('No complete Windows package or IIS FastCGI mapping audit','Version resources are not vendor backport proof','Static occurrences are not effective runtime configuration','Review IIS handlerMappings/FastCGI application paths locally without exporting secrets','This script has not been executed on Windows in release validation')
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding UTF8
Write-Output "Inventory written. Restrict the output ACL according to organizational policy. No vulnerability verdict issued."
