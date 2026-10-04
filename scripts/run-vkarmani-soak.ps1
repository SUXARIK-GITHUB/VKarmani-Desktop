<# Read-only observation of a manually started candidate. Never starts/stops a
VPN, reads AppData/configs/credentials or changes network state. Run in a
disposable Windows account/VM with synthetic or explicitly authorized profiles.
Reports duration actually observed, not intended duration. Ctrl+C is partial.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][int]$AppProcessId,
  [Parameter(Mandatory)][string]$ExpectedExePath,
  [Parameter(Mandatory)][string]$ReportPath,
  [ValidateSet(1,8,24)][int]$DurationHours = 1,
  [ValidateRange(1,300)][int]$IntervalSeconds = 30,
  [ValidateRange(0,60)][int]$QuickValidationSeconds = 0
)
$ErrorActionPreference = 'Stop'
$app = Get-Process -Id $AppProcessId
$expected = [IO.Path]::GetFullPath($ExpectedExePath)
if ($app.Path -ine $expected) { throw 'Process path does not match candidate' }
$startIdentity = $app.StartTime.ToUniversalTime().Ticks
$report = [IO.Path]::GetFullPath($ReportPath)
if (Test-Path -LiteralPath $report) { throw 'Report already exists; refusing overwrite' }
$parent = Split-Path -Parent $report
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Create report parent first' }
$writer = [IO.StreamWriter]::new([IO.File]::Open($report,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read),[Text.UTF8Encoding]::new($false))
$timer = [Diagnostics.Stopwatch]::StartNew()
$seconds = $DurationHours * 3600
if ($QuickValidationSeconds -gt 0) { $seconds = $QuickValidationSeconds }
$samples = 0; $complete = $false; $failure = $null
try {
  $writer.WriteLine((@{type='start';schema=1;requestedHours=$DurationHours;quickValidationSeconds=$QuickValidationSeconds;scope='readonly process metrics; no VPN control';utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress))
  do {
    $app = Get-Process -Id $AppProcessId
    if ($app.Path -ine $expected -or $app.StartTime.ToUniversalTime().Ticks -ne $startIdentity) { throw 'Candidate exited or PID reused' }
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $AppProcessId" | Where-Object Name -eq 'xray.exe')
    $metrics = @($app) + @($children | ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    $rows = @($metrics | ForEach-Object { @{pid=$_.Id;name=$_.ProcessName;workingSetBytes=$_.WorkingSet64;privateBytes=$_.PrivateMemorySize64;handles=$_.HandleCount;threads=$_.Threads.Count;cpuSeconds=$_.CPU} })
    $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.InterfaceAlias -in @('vkarmani-tun','VKarmaniTun') -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') })
    $writer.WriteLine((@{type='sample';elapsedSeconds=$timer.Elapsed.TotalSeconds;utc=[DateTime]::UtcNow.ToString('o');processes=$rows;proxyEnabled=($proxy.ProxyEnable -eq 1);pacPresent=([bool]$proxy.AutoConfigURL);tunHalfDefaultCount=$routes.Count} | ConvertTo-Json -Depth 5 -Compress))
    $writer.Flush(); $samples++
    if ($timer.Elapsed.TotalSeconds -ge $seconds) { $complete=$true; break }
    Start-Sleep -Seconds ([Math]::Min($IntervalSeconds,[Math]::Max(1,[Math]::Ceiling($seconds-$timer.Elapsed.TotalSeconds))))
  } while ($true)
} catch { $failure='Observation failed; inspect candidate/environment without recording private values'; throw }
finally {
  $writer.WriteLine((@{type='finish';actualDurationSeconds=$timer.Elapsed.TotalSeconds;samples=$samples;observationComplete=$complete;vpnAcceptance='NOT_RUN by this observer';failure=$failure} | ConvertTo-Json -Compress))
  $writer.Dispose()
}
