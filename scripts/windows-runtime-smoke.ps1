<#
  VKarmani Desktop Windows runtime smoke checks.

  Run from PowerShell on Windows before/after a local build test. The script does not need
  secrets and does not start a real VPN profile by itself; it verifies the bundled Xray-core,
  leftover routes, system proxy state, active DNS servers, and common runtime cache files.

  Recommended manual flow on a real Windows machine:
    1. Run once before connecting:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows-runtime-smoke.ps1 -RequireCleanDisconnect
    2. Connect in Proxy mode, browse to ipleak.net / browserleaks.com/dns, then disconnect.
    3. Connect in TUN mode, browse to ipleak.net / browserleaks.com/dns, then disconnect.
    4. Run again:              powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows-runtime-smoke.ps1 -RequireCleanDisconnect -CheckDnsSnapshot
#>
param(
  [switch]$RequireCleanDisconnect,
  [switch]$CheckDnsSnapshot,
  [string]$AppDataVendor = 'com.vkarmani.desktop'
)

$ErrorActionPreference = 'Stop'

function Write-Step($Text) {
  Write-Host "[vkarmani-smoke] $Text"
}

function Write-Section($Text) {
  Write-Host ""
  Write-Host "[vkarmani-smoke] === $Text ==="
}

function Test-CommandAvailable($Name) {
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

$root = Split-Path -Parent $PSScriptRoot
$core = Join-Path $root 'resources/core/windows'
$manifest = Join-Path $core 'core-manifest.json'

Write-Section "Bundled Xray-core manifest"
if (-not (Test-Path $manifest)) { throw "Missing core-manifest.json: $manifest" }
$manifestJson = Get-Content $manifest -Raw | ConvertFrom-Json
foreach ($entry in $manifestJson.files) {
  $path = Join-Path $core $entry.file
  if (-not (Test-Path $path)) { throw "Missing bundled core artifact: $($entry.file)" }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
  if ($hash -ne $entry.sha256.ToLowerInvariant()) {
    throw "SHA256 mismatch for $($entry.file): expected $($entry.sha256), got $hash"
  }
  Write-Step "OK $($entry.file)"
}

$xrayExe = Join-Path $core 'xray.exe'
if (Test-Path $xrayExe) {
  $xrayVersion = & $xrayExe version 2>$null | Select-Object -First 1
  if (-not $xrayVersion) { throw "Bundled xray.exe is present but did not return version output." }
  Write-Step "xray.exe launch OK: $xrayVersion"
}

Write-Section "VKarmani route leftovers"
$ipv4Leftovers = @()
$ipv6Leftovers = @()
if (Test-CommandAvailable 'Get-NetRoute') {
  $ipv4Leftovers = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -eq 'VKarmaniTun' -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') })
  $ipv6Leftovers = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -eq 'VKarmaniTun' -and $_.DestinationPrefix -in @('::/1','8000::/1') })
} else {
  Write-Warning "Get-NetRoute is unavailable; route leftovers check skipped."
}

if ($ipv4Leftovers.Count -gt 0 -or $ipv6Leftovers.Count -gt 0) {
  $message = "Found VKarmaniTun split-default route leftovers. Use Diagnostics -> Runtime repair while VPN is disconnected."
  if ($RequireCleanDisconnect) { throw $message }
  Write-Warning $message
} else {
  Write-Step "No VKarmaniTun split-default leftovers found"
}

Write-Section "Temporary direct /32 route snapshot"
if (Test-CommandAvailable 'Get-NetRoute') {
  $tmpRoutes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -match '^\d+\.\d+\.\d+\.\d+/32$' -and $_.RouteMetric -le 5 } |
    Sort-Object DestinationPrefix, InterfaceIndex |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, InterfaceIndex, RouteMetric)
  if ($tmpRoutes.Count -gt 0) {
    Write-Host ($tmpRoutes | Format-Table -AutoSize | Out-String)
    Write-Step "Found low-metric /32 routes. This can be normal while ping check is running; after disconnect/ping completion they should disappear."
  } else {
    Write-Step "No low-metric temporary /32 routes found"
  }
}

Write-Section "Current-user Windows proxy"
$proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxy = Get-ItemProperty -Path $proxyKey
Write-Step "ProxyEnable=$($proxy.ProxyEnable) ProxyServer=$($proxy.ProxyServer)"
$proxyEnableValue = 0
if ($null -ne $proxy.ProxyEnable) { $proxyEnableValue = [int]$proxy.ProxyEnable }
if ($RequireCleanDisconnect -and $proxyEnableValue -ne 0) {
  throw "System proxy is enabled while clean disconnect was required. Open VKarmani Diagnostics -> Runtime repair or disable Windows proxy manually."
}

Write-Section "Runtime cache privacy check"
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
$appDataRoot = Join-Path $localAppData $AppDataVendor
$clientState = Join-Path $appDataRoot 'client-state-v1.json'
$sensitiveState = Join-Path $appDataRoot 'sensitive-client-state-v1.dpapi'
if (Test-Path $clientState) {
  $clientStateText = Get-Content -LiteralPath $clientState -Raw -ErrorAction SilentlyContinue
  if ($clientStateText -match 'runtimeTemplate|rawUri') {
    $message = "Plain client-state-v1.json still contains runtimeTemplate/rawUri. Start the updated app once so it migrates the public cache, or clear old app data."
    if ($RequireCleanDisconnect) { throw $message }
    Write-Warning $message
  } else {
    Write-Step "Plain client-state-v1.json does not contain runtimeTemplate/rawUri"
  }
} else {
  Write-Step "Plain client-state-v1.json not found yet"
}
if (Test-Path $sensitiveState) {
  Write-Step "Encrypted sensitive-client-state-v1.dpapi exists"
} else {
  Write-Step "Encrypted sensitive-client-state-v1.dpapi not found yet; it appears after profile sync/save."
}

if ($CheckDnsSnapshot) {
  Write-Section "DNS snapshot"
  if (Test-CommandAvailable 'Get-DnsClientServerAddress') {
    $dnsRows = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
      Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses
    Write-Host ($dnsRows | Format-Table -AutoSize | Out-String)
    Write-Step "For a real DNS leak test, compare browserleaks.com/dns or ipleak.net while Proxy/TUN is connected."
  } else {
    Write-Warning "Get-DnsClientServerAddress is unavailable; DNS snapshot skipped."
  }
}

Write-Section "Result"
Write-Step "Smoke checks completed"
