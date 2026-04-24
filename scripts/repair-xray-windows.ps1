param(
  [string]$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'
$coreDir = Join-Path $ProjectDir 'resources\core\windows'
$manifestPath = Join-Path $coreDir 'core-manifest.json'
$required = @('xray.exe', 'geoip.dat', 'geosite.dat', 'wintun.dll')

function Write-Info([string]$Message) {
  Write-Host "[INFO] $Message"
}

function Write-WarnLine([string]$Message) {
  Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrLine([string]$Message) {
  Write-Host "[ERROR] $Message" -ForegroundColor Red
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

  return $problems
}

if (-not (Test-Path -LiteralPath $coreDir)) {
  New-Item -ItemType Directory -Force -Path $coreDir | Out-Null
}

$problems = Test-CoreFiles
if ($problems.Count -eq 0) {
  Write-Info 'Xray-core files are present and valid.'
  exit 0
}

Write-WarnLine 'Xray-core validation found problems:'
$problems | ForEach-Object { Write-WarnLine " - $_" }

$git = Get-Command git -ErrorAction SilentlyContinue
$gitDir = Join-Path $ProjectDir '.git'
if ($git -and (Test-Path -LiteralPath $gitDir)) {
  Write-Info 'Trying to restore bundled core files from git...'
  & git -C $ProjectDir checkout -- `
    resources/core/windows/xray.exe `
    resources/core/windows/geoip.dat `
    resources/core/windows/geosite.dat `
    resources/core/windows/wintun.dll `
    resources/core/windows/core-manifest.json | Out-Host

  $problems = Test-CoreFiles
  if ($problems.Count -eq 0) {
    Write-Info 'Xray-core files restored successfully.'
    exit 0
  }
}

Write-ErrLine 'Xray-core files are still missing or corrupted.'
Write-ErrLine "Expected directory: $coreDir"
Write-ErrLine 'Required files: xray.exe, geoip.dat, geosite.dat, wintun.dll'
Write-ErrLine 'Fix: use the full repository/archive that contains resources/core/windows, or restore these files before running/building.'
exit 1
