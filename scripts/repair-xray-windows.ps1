param(
  [string]$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'
$coreDir = Join-Path $ProjectDir 'resources\core\windows'
$manifestPath = Join-Path $coreDir 'core-manifest.json'
$fetchScript = Join-Path $PSScriptRoot 'fetch-xray-windows.ps1'
$required = @('xray.exe', 'geoip.dat', 'geosite.dat', 'wintun.dll')

function Write-Info([string]$Message) { Write-Host "[INFO] $Message" }
function Write-WarnLine([string]$Message) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-ErrLine([string]$Message) { Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Test-XrayLaunch([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }

  $stdout = $null
  $stderr = $null
  try {
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath $Path -ArgumentList @('version') -WorkingDirectory (Split-Path -Parent $Path) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    return $process.ExitCode -eq 0
  } catch {
    # Do not print a scary startup warning here. A bundled core can fail to launch
    # after unzip/quarantine/AV interference; the caller will repair it automatically.
    return $false
  } finally {
    if ($stdout) { Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue }
    if ($stderr) { Remove-Item -LiteralPath $stderr -Force -ErrorAction SilentlyContinue }
  }
}

function Test-WindowsX64Pe([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 1024) { return $false }
    if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return $false }
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
    if ($peOffset -lt 64 -or $peOffset + 26 -ge $bytes.Length) { return $false }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) { return $false }
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $magic = [BitConverter]::ToUInt16($bytes, $peOffset + 24)
    return ($machine -eq 0x8664 -and $magic -eq 0x20B)
  } catch {
    Write-WarnLine "$Label PE validation failed: $($_.Exception.Message)"
    return $false
  }
}

function Get-PackageVersionSafe {
  $packagePath = Join-Path $ProjectDir 'package.json'
  try {
    if (Test-Path -LiteralPath $packagePath -PathType Leaf) {
      return ([string]((Get-Content -LiteralPath $packagePath -Raw -Encoding UTF8 | ConvertFrom-Json).version))
    }
  } catch {
    Write-WarnLine "Could not read package.json version: $($_.Exception.Message)"
  }
  return '0.13.40'
}

function Write-CoreManifestNoBom {
  foreach ($file in $required) {
    $path = Join-Path $coreDir $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      throw "$file is missing, cannot regenerate core-manifest.json"
    }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -le 0) {
      throw "$file is empty, cannot regenerate core-manifest.json"
    }
  }

  $xrayPath = Join-Path $coreDir 'xray.exe'
  $wintunPath = Join-Path $coreDir 'wintun.dll'
  if (-not (Test-WindowsX64Pe $xrayPath 'xray.exe')) {
    throw 'xray.exe is not a valid Windows x64 PE file, cannot regenerate manifest'
  }
  if (-not (Test-WindowsX64Pe $wintunPath 'wintun.dll')) {
    throw 'wintun.dll is not a valid Windows x64 PE file, cannot regenerate manifest'
  }

  $files = @()
  foreach ($file in $required) {
    $path = Join-Path $coreDir $file
    $item = Get-Item -LiteralPath $path
    $files += [ordered]@{
      file = $file
      size = [int64]$item.Length
      sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }

  $manifest = [ordered]@{
    version = (Get-PackageVersionSafe)
    generatedFor = 'VKarmani Desktop bundled core artifacts'
    files = $files
  }

  $json = ($manifest | ConvertTo-Json -Depth 6) + "`n"
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($manifestPath, $json, $utf8NoBom)
}

function Test-ManifestHasUtf8Bom {
  if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return $false }
  try {
    $stream = [System.IO.File]::OpenRead($manifestPath)
    try {
      if ($stream.Length -lt 3) { return $false }
      $buffer = New-Object byte[] 3
      [void]$stream.Read($buffer, 0, 3)
      return ($buffer[0] -eq 0xEF -and $buffer[1] -eq 0xBB -and $buffer[2] -eq 0xBF)
    } finally {
      $stream.Dispose()
    }
  } catch {
    return $false
  }
}

function Try-RegenerateManifestNoBom {
  try {
    Write-Info 'Regenerating core-manifest.json as UTF-8 without BOM...'
    Write-CoreManifestNoBom
    return $true
  } catch {
    Write-WarnLine "Manifest regeneration failed: $($_.Exception.Message)"
    return $false
  }
}

function Test-CoreFiles {
  $problems = New-Object System.Collections.Generic.List[string]
  $manifest = $null

  if (Test-Path -LiteralPath $manifestPath) {
    try {
      $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
      $problems.Add("core-manifest.json cannot be parsed: $($_.Exception.Message)")
    }
  } else {
    $problems.Add('core-manifest.json is missing')
  }

  foreach ($file in $required) {
    $path = Join-Path $coreDir $file

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      $problems.Add("$file is missing")
      continue
    }

    $item = Get-Item -LiteralPath $path
    if ($item.Length -le 0) {
      $problems.Add("$file is empty")
      continue
    }

    if ($file -eq 'xray.exe' -and $item.Length -lt 1000000) {
      $problems.Add('xray.exe is suspiciously small and looks corrupted')
      continue
    }

    if ($manifest -and $manifest.files) {
      $expected = $manifest.files | Where-Object { $_.file -eq $file } | Select-Object -First 1
      if ($expected) {
        if ([Int64]$expected.size -ne [Int64]$item.Length) {
          $problems.Add("$file size mismatch: manifest=$($expected.size), actual=$($item.Length)")
          continue
        }

        if ($expected.sha256) {
          $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
          if ($actualHash -ne [string]$expected.sha256) {
            $problems.Add("$file sha256 mismatch")
            continue
          }
        }
      }
    }
  }

  $xrayPath = Join-Path $coreDir 'xray.exe'
  if (-not (Test-WindowsX64Pe $xrayPath 'xray.exe')) {
    $problems.Add('xray.exe is not a valid Windows x64 PE file')
  }

  $wintunPath = Join-Path $coreDir 'wintun.dll'
  if (-not (Test-WindowsX64Pe $wintunPath 'wintun.dll')) {
    $problems.Add('wintun.dll is not a valid Windows x64 PE file')
  }

  if ((Test-Path -LiteralPath $xrayPath -PathType Leaf) -and -not (Test-XrayLaunch $xrayPath)) {
    $problems.Add('xray.exe cannot launch on this Windows installation')
  }

  return $problems
}

function Try-AutomaticFetchRepair {
  if (-not (Test-Path -LiteralPath $fetchScript -PathType Leaf)) { return $false }

  Write-Info 'Xray-core needs automatic repair; trying to download official Windows x64 Xray-core...'
  try {
    & $fetchScript -ProjectDir $ProjectDir -Force
    return $true
  } catch {
    Write-WarnLine "Xray automatic repair failed: $($_.Exception.Message)"
    return $false
  }
}

function Try-GitRestoreRepair {
  $git = Get-Command git -ErrorAction SilentlyContinue
  $gitDir = Join-Path $ProjectDir '.git'
  if (-not $git -or -not (Test-Path -LiteralPath $gitDir)) { return $false }

  Write-Info 'Trying to restore bundled core files from git...'
  try {
    & git -C $ProjectDir checkout -- `
      resources/core/windows/xray.exe `
      resources/core/windows/geoip.dat `
      resources/core/windows/geosite.dat `
      resources/core/windows/wintun.dll `
      resources/core/windows/core-manifest.json | Out-Host
    return $LASTEXITCODE -eq 0
  } catch {
    Write-WarnLine "Git restore failed: $($_.Exception.Message)"
    return $false
  }
}

if (-not (Test-Path -LiteralPath $coreDir)) {
  New-Item -ItemType Directory -Force -Path $coreDir | Out-Null
}

$problems = Test-CoreFiles
if ($problems.Count -eq 0) {
  if (Test-ManifestHasUtf8Bom) {
    Write-Info 'core-manifest.json has UTF-8 BOM; rewriting without BOM for Rust serde_json compatibility.'
    if (-not (Try-RegenerateManifestNoBom)) {
      Write-ErrLine 'Could not rewrite core-manifest.json without BOM.'
      exit 1
    }
    $problems = Test-CoreFiles
    if ($problems.Count -ne 0) {
      Write-WarnLine 'Xray-core validation failed after manifest rewrite:'
      $problems | ForEach-Object { Write-WarnLine " - $_" }
      exit 1
    }
  }
  Write-Info 'Xray-core files are present and pass manifest/PE/launch validation.'
  exit 0
}

if ($problems | Where-Object { $_ -like 'core-manifest.json cannot be parsed*' -or $_ -eq 'core-manifest.json is missing' }) {
  if (Try-RegenerateManifestNoBom) {
    $problems = Test-CoreFiles
    if ($problems.Count -eq 0) {
      Write-Info 'Xray-core manifest repaired successfully.'
      exit 0
    }
  }
}

Write-Info 'Preparing Xray-core runtime files; automatic repair will be attempted if needed.'
if ($env:VKARMANI_VERBOSE_REPAIR -eq '1') {
  $problems | ForEach-Object { Write-Info " - $_" }
}

if (Try-AutomaticFetchRepair) {
  $problems = Test-CoreFiles
  if ($problems.Count -eq 0) {
    if (Test-ManifestHasUtf8Bom) { [void](Try-RegenerateManifestNoBom) }
    Write-Info 'Xray-core files repaired successfully.'
    exit 0
  }
}

if (Try-GitRestoreRepair) {
  $problems = Test-CoreFiles
  if ($problems.Count -eq 0) {
    if (Test-ManifestHasUtf8Bom) { [void](Try-RegenerateManifestNoBom) }
    Write-Info 'Xray-core files restored successfully.'
    exit 0
  }
}

Write-WarnLine 'Xray-core validation still found problems after automatic repair:'
$problems | ForEach-Object { Write-WarnLine " - $_" }

Write-ErrLine 'Xray-core files are still missing, corrupted, or not valid Windows x64 files.'
Write-ErrLine "Expected directory: $coreDir"
Write-ErrLine 'Required files: xray.exe, geoip.dat, geosite.dat, wintun.dll'
Write-ErrLine 'Fix: run scripts/fetch-xray-windows.ps1 or use the GitHub Actions release artifact built from v0.13.40 or newer.'
exit 1
