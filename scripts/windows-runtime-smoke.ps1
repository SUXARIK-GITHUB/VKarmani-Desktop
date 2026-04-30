<#
  VKarmani Desktop Windows runtime smoke checks.
  Run from an elevated PowerShell after installing a local build.
  This script does not need secrets and does not start a real VPN profile by itself;
  it verifies cleanup/repair expectations around routes, proxy and bundled core files.
#>
$ErrorActionPreference = 'Stop'

function Write-Step($Text) {
  Write-Host "[vkarmani-smoke] $Text"
}

$root = Split-Path -Parent $PSScriptRoot
$core = Join-Path $root 'resources/core/windows'
$manifest = Join-Path $core 'core-manifest.json'

Write-Step "Checking bundled core manifest"
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

Write-Step "Checking VKarmaniTun route leftovers"
$ipv4Leftovers = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.InterfaceAlias -eq 'VKarmaniTun' -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }
$ipv6Leftovers = Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
  Where-Object { $_.InterfaceAlias -eq 'VKarmaniTun' -and $_.DestinationPrefix -in @('::/1','8000::/1') }
if ($ipv4Leftovers -or $ipv6Leftovers) {
  Write-Warning "Found VKarmaniTun route leftovers. Use Diagnostics -> Runtime repair while VPN is disconnected."
} else {
  Write-Step "No VKarmaniTun split-default leftovers found"
}

Write-Step "Checking current-user Windows proxy"
$proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxy = Get-ItemProperty -Path $proxyKey
Write-Step "ProxyEnable=$($proxy.ProxyEnable) ProxyServer=$($proxy.ProxyServer)"

Write-Step "Smoke checks completed"
