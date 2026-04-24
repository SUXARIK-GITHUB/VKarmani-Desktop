param(
  [string]$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
  [string]$XrayVersion = 'v26.3.27',
  [string]$ExpectedZipSha256 = 'd004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad',
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$coreDir = Join-Path $ProjectDir 'resources\core\windows'
$manifestPath = Join-Path $coreDir 'core-manifest.json'
$packageJsonPath = Join-Path $ProjectDir 'package.json'

function Write-Info([string]$Message) { Write-Host "[xray-fetch] $Message" }
function Write-WarnLine([string]$Message) { Write-Host "[xray-fetch] WARN: $Message" -ForegroundColor Yellow }

function Get-PackageVersion {
  if (Test-Path -LiteralPath $packageJsonPath) {
    try {
      return ((Get-Content -LiteralPath $packageJsonPath -Raw -Encoding UTF8) | ConvertFrom-Json).version
    } catch {
      Write-WarnLine "Cannot parse package.json version: $($_.Exception.Message)"
    }
  }

  return '0.0.0'
}

function Test-XrayLaunch([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }

  try {
    $coreWorkDir = Split-Path -Parent $Path
    $process = Start-Process -FilePath $Path -ArgumentList @('version') -WorkingDirectory $coreWorkDir -NoNewWindow -Wait -PassThru -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) -RedirectStandardError ([System.IO.Path]::GetTempFileName())
    return $process.ExitCode -eq 0
  } catch {
    return $false
  }
}

function Get-FileEntry([string]$FileName) {
  $path = Join-Path $coreDir $FileName
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Missing core file after Xray fetch: $FileName"
  }

  $item = Get-Item -LiteralPath $path
  [ordered]@{
    file = $FileName
    size = [int64]$item.Length
    sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

if (-not (Test-Path -LiteralPath $coreDir)) {
  New-Item -ItemType Directory -Force -Path $coreDir | Out-Null
}

$xrayPath = Join-Path $coreDir 'xray.exe'
if (-not $Force -and (Test-XrayLaunch $xrayPath)) {
  Write-Info "Existing xray.exe launches successfully; keeping bundled file."
  exit 0
}

Write-Info "Downloading official Xray-core Windows x64 $XrayVersion because bundled xray.exe is missing or not launchable."

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("vkarmani-xray-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zipPath = Join-Path $tmp 'Xray-windows-64.zip'

$urls = @(
  "https://github.com/XTLS/Xray-core/releases/download/$XrayVersion/Xray-windows-64.zip",
  "https://downloads.sourceforge.net/project/xray-core.mirror/$XrayVersion/Xray-windows-64.zip"
)

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $downloaded = $false
  foreach ($url in $urls) {
    try {
      Write-Info "Trying $url"
      Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -MaximumRedirection 10
      if ((Test-Path -LiteralPath $zipPath) -and ((Get-Item -LiteralPath $zipPath).Length -gt 1000000)) {
        $downloaded = $true
        break
      }
    } catch {
      Write-WarnLine "Download failed from $url: $($_.Exception.Message)"
    }
  }

  if (-not $downloaded) {
    throw 'Cannot download Xray-windows-64.zip from GitHub or SourceForge mirror.'
  }

  $actualZipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($ExpectedZipSha256 -and $actualZipHash -ne $ExpectedZipSha256.ToLowerInvariant()) {
    throw "Downloaded Xray ZIP sha256 mismatch. Expected=$ExpectedZipSha256 Actual=$actualZipHash"
  }
  Write-Info "Xray ZIP sha256 verified: $actualZipHash"

  $extractDir = Join-Path $tmp 'extract'
  New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
  Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

  foreach ($name in @('xray.exe', 'geoip.dat', 'geosite.dat')) {
    $src = Get-ChildItem -LiteralPath $extractDir -Recurse -File -Filter $name | Select-Object -First 1
    if (-not $src) {
      throw "Downloaded Xray archive does not contain $name"
    }
    Copy-Item -LiteralPath $src.FullName -Destination (Join-Path $coreDir $name) -Force
  }

  if (-not (Test-XrayLaunch $xrayPath)) {
    throw "Downloaded xray.exe still cannot run. Check Windows architecture, antivirus quarantine, or corrupted download."
  }

  $files = @()
  foreach ($name in @('xray.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat')) {
    $files += (Get-FileEntry $name)
  }

  $manifest = [ordered]@{
    version = (Get-PackageVersion)
    xrayCoreVersion = $XrayVersion
    generatedFor = 'VKarmani Desktop bundled core artifacts'
    files = $files
  }

  ($manifest | ConvertTo-Json -Depth 6) + "`n" | Set-Content -LiteralPath $manifestPath -Encoding UTF8
  Write-Info "Updated core manifest: $manifestPath"
  Write-Info "Xray-core Windows x64 $XrayVersion is ready."
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
