param([string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) ('vkarmani-resource-tests-' + [Guid]::NewGuid().ToString('N'))))
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'core-resource-tools.psm1') -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path -LiteralPath $WorkDir) { throw 'Test directory must be new; existing data is never overwritten.' }
[IO.Directory]::CreateDirectory($WorkDir) | Out-Null
$script:count = 0
function Must-Reject([string]$Label, [scriptblock]$Action) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  if (-not $rejected) { throw "Expected rejection: $Label" }
  $script:count++; Write-Host "PASS reject: $Label"
}
function New-Archive([string]$Path, [string[]]$Names) {
  $zip = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($name in $Names) {
      $entry = $zip.CreateEntry($name)
      $stream = $entry.Open()
      try { $stream.WriteByte(1) } finally { $stream.Dispose() }
    }
  } finally { $zip.Dispose() }
}
foreach ($url in @('http://github.com/a', 'https://user:secret@github.com/a', 'https://github.com:444/a', 'https://github.com.evil.example/a', 'https://127.0.0.1/a', 'file:///C:/a')) {
  Must-Reject $url { Assert-ResourceUrl $url }
}
Assert-ResourceUrl 'https://release-assets.githubusercontent.com/github-production-release-asset/a'
$script:count++; Write-Host 'PASS approved HTTPS upstream'
$i = 0
foreach ($names in @(@('../escape'), @('/absolute'), @('C:/absolute'), @('file:stream'), @('folder\escape'), @('same', 'SAME'))) {
  $i++
  $archive = Join-Path $WorkDir "bad-$i.zip"
  New-Archive $archive $names
  $extract = Join-Path $WorkDir "bad-$i"
  Must-Reject "archive $i" { Expand-SafeResourceArchive $archive $extract }
  if (Test-Path -LiteralPath $extract) { throw 'Invalid archive wrote an extraction directory.' }
}
$archive = Join-Path $WorkDir 'valid.zip'
New-Archive $archive @('folder/file')
Expand-SafeResourceArchive $archive (Join-Path $WorkDir 'valid')
if ((Get-Item -LiteralPath (Join-Path $WorkDir 'valid/folder/file')).Length -ne 1) { throw 'Valid archive extraction mismatch.' }
$script:count++; Write-Host 'PASS valid archive'
$bundle = Join-Path $WorkDir ('.windows-stage-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($bundle) | Out-Null
$pe = New-Object byte[] 512
[BitConverter]::GetBytes([uint16]23117).CopyTo($pe, 0)
[BitConverter]::GetBytes([uint32]128).CopyTo($pe, 60)
[BitConverter]::GetBytes([uint32]17744).CopyTo($pe, 128)
[BitConverter]::GetBytes([uint16]34404).CopyTo($pe, 132)
[BitConverter]::GetBytes([uint16]523).CopyTo($pe, 152)
foreach ($name in @('xray.exe', 'wintun.dll')) { [IO.File]::WriteAllBytes((Join-Path $bundle $name), $pe) }
foreach ($name in @('geoip.dat', 'geosite.dat')) { [IO.File]::WriteAllBytes((Join-Path $bundle $name), [byte[]]@(1,2,3)) }
$entries = foreach ($name in @('xray.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat')) {
  $path = Join-Path $bundle $name
  @{ file = $name; size = (Get-Item -LiteralPath $path).Length; sha256 = (Get-FileHash -LiteralPath $path).Hash }
}
$manifestPath = Join-Path $bundle 'core-manifest.json'
function Save-Manifest($Items) { [IO.File]::WriteAllText($manifestPath, (@{files = @($Items)} | ConvertTo-Json -Depth 5)) }
Save-Manifest $entries
Assert-CoreBundle $bundle
$script:count++; Write-Host 'PASS exact bundle'
Save-Manifest @($entries + $entries[0])
Must-Reject 'duplicate manifest entry' { Assert-CoreBundle $bundle }
Save-Manifest $entries
$wrong = $pe.Clone(); $wrong[132] = 76; $wrong[133] = 1
[IO.File]::WriteAllBytes((Join-Path $bundle 'xray.exe'), $wrong)
Must-Reject 'wrong architecture' { Assert-WindowsAmd64Pe (Join-Path $bundle 'xray.exe') }
Must-Reject 'same-size corrupt binary' { Assert-CoreBundle $bundle }
[IO.File]::WriteAllBytes((Join-Path $bundle 'xray.exe'), $pe)
[IO.File]::WriteAllBytes((Join-Path $bundle 'geoip.dat'), [byte[]]@(1,2))
Must-Reject 'partial resource' { Assert-CoreBundle $bundle }
[IO.File]::WriteAllBytes((Join-Path $bundle 'geoip.dat'), [byte[]]@(1,2,3))
Must-Reject 'publication outside owned destination' { Publish-CoreBundle $bundle (Join-Path $WorkDir 'foreign') }
$destination = Join-Path $WorkDir 'windows'
$backup = Publish-CoreBundle $bundle $destination
Assert-CoreBundle $destination
$script:count++; Write-Host 'PASS complete-set publication'
[IO.File]::WriteAllText((Join-Path $WorkDir '.windows-replacement.json'), 'incomplete previous transaction')
$stage2 = Join-Path $WorkDir ('.windows-stage-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stage2) | Out-Null
Get-ChildItem -LiteralPath $destination -File | Copy-Item -Destination $stage2
Must-Reject 'interrupted prior publication' { Publish-CoreBundle $stage2 $destination }
Assert-CoreBundle $destination
Write-Host "PASS $script:count resource checks. Retained synthetic artifacts: $WorkDir"
