$ErrorActionPreference = 'Stop'

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$CoreDir = Join-Path $Root 'resources\core\windows'
$XrayPath = Join-Path $CoreDir 'xray.exe'
$WintunPath = Join-Path $CoreDir 'wintun.dll'

function Read-HeaderBytes([string]$Path, [int]$Count = 4096) {
  $stream = [System.IO.File]::OpenRead($Path)
  try {
    $buffer = New-Object byte[] $Count
    $read = $stream.Read($buffer, 0, $buffer.Length)
    if ($read -lt $Count) {
      $small = New-Object byte[] $read
      [Array]::Copy($buffer, $small, $read)
      return $small
    }
    return $buffer
  } finally {
    $stream.Dispose()
  }
}

function Assert-WindowsX64Pe([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Label is missing: $Path"
  }

  $item = Get-Item -LiteralPath $Path
  if ($item.Length -lt 1024) {
    throw "$Label is suspiciously small: $($item.Length) bytes"
  }

  $header = Read-HeaderBytes $Path 4096
  if ($header.Length -lt 256) {
    throw "$Label header is too small: $($header.Length) bytes"
  }

  $prefix = [System.Text.Encoding]::ASCII.GetString($header, 0, [Math]::Min(32, $header.Length))
  if ($prefix.StartsWith('version https://git-lfs')) {
    throw "$Label is a Git LFS pointer, not a real binary. Use actions/checkout with lfs:true."
  }

  if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) {
    $first = ($header[0..15] | ForEach-Object { $_.ToString('X2') }) -join ' '
    throw "$Label has invalid MZ header. First bytes: $first"
  }

  $peOffset = [BitConverter]::ToUInt32($header, 0x3C)
  if ($peOffset -lt 64 -or $peOffset -gt 8192 -or ($peOffset + 26) -gt $header.Length) {
    throw "$Label has invalid PE offset: $peOffset"
  }

  if ($header[$peOffset] -ne 0x50 -or $header[$peOffset + 1] -ne 0x45 -or $header[$peOffset + 2] -ne 0 -or $header[$peOffset + 3] -ne 0) {
    throw "$Label has invalid PE signature at offset $peOffset"
  }

  $machine = [BitConverter]::ToUInt16($header, $peOffset + 4)
  if ($machine -ne 0x8664) {
    throw "$Label must be Windows x64/AMD64 PE. Machine=0x$($machine.ToString('X4'))"
  }

  $magic = [BitConverter]::ToUInt16($header, $peOffset + 24)
  if ($magic -ne 0x20B) {
    throw "$Label must be PE32+ x64. OptionalHeader=0x$($magic.ToString('X4'))"
  }

  Write-Host "[xray-check] OK: $Label is Windows x64 PE32+ ($($item.Length) bytes)"
}

Assert-WindowsX64Pe $XrayPath 'xray.exe'
Assert-WindowsX64Pe $WintunPath 'wintun.dll'

Write-Host '[xray-check] Running xray.exe version...'
& $XrayPath version
if ($LASTEXITCODE -ne 0) {
  throw "xray.exe version failed with exit code $LASTEXITCODE"
}
Write-Host '[xray-check] OK: xray.exe version runs on Windows runner'
