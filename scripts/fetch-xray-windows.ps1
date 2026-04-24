param(
  [string]$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
  [string]$XrayVersion = 'v26.3.27',
  [string]$ExpectedZipSha256 = '',
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

  $stdout = $null
  $stderr = $null
  try {
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $coreWorkDir = Split-Path -Parent $Path
    $process = Start-Process -FilePath $Path -ArgumentList @('version') -WorkingDirectory $coreWorkDir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    return $process.ExitCode -eq 0
  } catch {
    return $false
  } finally {
    if ($stdout) { Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue }
    if ($stderr) { Remove-Item -LiteralPath $stderr -Force -ErrorAction SilentlyContinue }
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

function Get-Sha256FromDigestFile([string]$DigestPath) {
  if (-not (Test-Path -LiteralPath $DigestPath -PathType Leaf)) {
    throw "Digest file is missing: $DigestPath"
  }

  $digestText = Get-Content -LiteralPath $DigestPath -Raw -Encoding UTF8
  $sha256Line = [regex]::Match($digestText, '(?im)^\s*SHA256\s*\([^)]*\)\s*=\s*([a-f0-9]{64})\s*$')
  if ($sha256Line.Success) {
    return $sha256Line.Groups[1].Value.ToLowerInvariant()
  }

  $anySha256 = [regex]::Match($digestText, '(?i)\b([a-f0-9]{64})\b')
  if ($anySha256.Success) {
    return $anySha256.Groups[1].Value.ToLowerInvariant()
  }

  throw "Digest file does not contain a SHA256 hash: $DigestPath"
}

function Invoke-Download([string]$Url, [string]$Destination) {
  Write-Info "Downloading ${Url}"
  Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -MaximumRedirection 10
  if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
    throw "Download did not create file: $Destination"
  }
}

if (-not (Test-Path -LiteralPath $coreDir)) {
  New-Item -ItemType Directory -Force -Path $coreDir | Out-Null
}

$xrayPath = Join-Path $coreDir 'xray.exe'
if (-not $Force -and (Test-XrayLaunch $xrayPath)) {
  Write-Info 'Existing xray.exe launches successfully; keeping bundled file.'
  exit 0
}

Write-Info "Downloading official Xray-core Windows x64 $XrayVersion because bundled xray.exe is missing or not launchable."

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("vkarmani-xray-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zipPath = Join-Path $tmp 'Xray-windows-64.zip'
$dgstPath = Join-Path $tmp 'Xray-windows-64.zip.dgst'

$sources = @(
  [ordered]@{
    Name = 'GitHub Releases'
    Zip = "https://github.com/XTLS/Xray-core/releases/download/$XrayVersion/Xray-windows-64.zip"
    Digest = "https://github.com/XTLS/Xray-core/releases/download/$XrayVersion/Xray-windows-64.zip.dgst"
  },
  [ordered]@{
    Name = 'SourceForge mirror'
    Zip = "https://downloads.sourceforge.net/project/xray-core.mirror/$XrayVersion/Xray-windows-64.zip"
    Digest = "https://downloads.sourceforge.net/project/xray-core.mirror/$XrayVersion/Xray-windows-64.zip.dgst"
  }
)

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $downloaded = $false
  $errors = New-Object System.Collections.Generic.List[string]

  foreach ($source in $sources) {
    try {
      Remove-Item -LiteralPath $zipPath, $dgstPath -Force -ErrorAction SilentlyContinue
      Write-Info "Trying $($source.Name)"

      Invoke-Download -Url $source.Zip -Destination $zipPath
      if ((Get-Item -LiteralPath $zipPath).Length -le 1000000) {
        throw 'Downloaded ZIP is suspiciously small.'
      }

      $expectedHash = $ExpectedZipSha256.Trim().ToLowerInvariant()
      if (-not $expectedHash) {
        Invoke-Download -Url $source.Digest -Destination $dgstPath
        $expectedHash = Get-Sha256FromDigestFile $dgstPath
      }

      $actualZipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($actualZipHash -ne $expectedHash) {
        throw "Downloaded Xray ZIP sha256 mismatch. Expected=$expectedHash Actual=$actualZipHash"
      }

      Write-Info "Xray ZIP sha256 verified: $actualZipHash"
      $downloaded = $true
      break
    } catch {
      $message = "$($source.Name) failed: $($_.Exception.Message)"
      $errors.Add($message) | Out-Null
      Write-WarnLine $message
    }
  }

  if (-not $downloaded) {
    throw "Cannot download and verify Xray-windows-64.zip. $($errors -join ' | ')"
  }

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
    throw 'Downloaded xray.exe still cannot run. Check Windows architecture, antivirus quarantine, or corrupted download.'
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
