<# Read-only smoke. Does not read/decrypt production state or change networking.
RequireCleanDisconnect is valid only after manual candidate disconnect.
A pre-existing user proxy/PAC is legitimate; it must be compared with its own
pre-test snapshot during live acceptance, never reset by this checker.
#>
param([switch]$RequireCleanDisconnect,[switch]$CheckDnsSnapshot,[string]$FixtureStateRoot)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'verify-xray-windows.ps1')
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'Core verification failed' }
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.InterfaceAlias -in @('vkarmani-tun','VKarmaniTun') -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') })
Write-Host "[vkarmani-smoke] TUN half-default route count=$($routes.Count)"
if ($RequireCleanDisconnect -and $routes.Count -gt 0) { throw 'TUN half-defaults present; ownership/live baseline review required. No cleanup attempted.' }
$proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Write-Host "[vkarmani-smoke] ProxyEnabled=$($proxy.ProxyEnable -eq 1) PACPresent=$([bool]$proxy.AutoConfigURL)"
Write-Host '[vkarmani-smoke] Proxy snapshot restoration: NOT_RUN (requires before/after owned live transaction)'
if ($FixtureStateRoot) {
  # Explicit synthetic fixture only. Default never opens production AppData.
  $file = Join-Path $FixtureStateRoot 'client-state-v1.json'
  if (Test-Path -LiteralPath $file) {
    if ((Get-Item -LiteralPath $file).Length -gt 2MB) { throw 'Fixture exceeds state limit' }
    if ((Get-Content -LiteralPath $file -Raw) -match 'runtimeTemplate|rawUri') { throw 'Fixture public state contains runtime secrets' }
  }
} else { Write-Host '[vkarmani-smoke] Private/public account cache content: NOT_RUN (no fixture supplied)' }
if ($CheckDnsSnapshot) {
  $rows = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses.Count -gt 0 })
  Write-Host "[vkarmani-smoke] DNS configured interface count=$($rows.Count); leak/traffic acceptance NOT_RUN"
}
Write-Host '[vkarmani-smoke] Read-only checks completed; no VPN/installer/packet acceptance claim'
