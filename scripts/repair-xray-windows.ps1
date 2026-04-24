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

  try {
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath $Path -ArgumentList @('version') -WorkingDirectory (Split-Path -Parent $Path) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    return $process.ExitCode -eq 0
  } catch {
    Write-WarnLine "xray.exe cannot launch: $($_.Exception.Message)"
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
  if (-not (Test-XrayLaunch $xrayPath)) {
    $problems.Add('xray.exe exists but does not launch as a valid Windows x64 application')
  }

  return $problems
}

if (-not (Test-Path -LiteralPath $coreDir)) {
  New-Item -ItemType Directory -Force -Path $coreDir | Out-Null
}

$problems = Test-CoreFiles
if ($problems.Count -eq 0) {
  Write-Info 'Xray-core files are present and launchable.'
  exit 0
}

Write-WarnLine 'Xray-core validation found problems:'
$problems | ForEach-Object { Write-WarnLine " - $_" }

if (Test-Path -LiteralPath $fetchScript -PathType Leaf) {
  Write-Info 'Trying to download official Windows x64 Xray-core...'
  & $fetchScript -ProjectDir $ProjectDir -Force
  $problems = Test-CoreFiles
  if ($problems.Count -eq 0) {
    Write-Info 'Xray-core files repaired successfully.'
    exit 0
  }
}

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

Write-ErrLine 'Xray-core files are still missing, corrupted, or not launchable.'
Write-ErrLine "Expected directory: $coreDir"
Write-ErrLine 'Required files: xray.exe, geoip.dat, geosite.dat, wintun.dll'
Write-ErrLine 'Fix: run scripts/fetch-xray-windows.ps1 or use the GitHub Actions release artifact built from v0.13.27 or newer.'
exit 1
