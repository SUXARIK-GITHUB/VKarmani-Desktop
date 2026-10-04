$ErrorActionPreference = 'Stop'

function Assert-ResourceUrl([string]$Url) {
  $uri = [Uri]$Url
  if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Port -ne 443) {
    throw 'Resource URL must be credential-free HTTPS on port 443.'
  }
  if ($uri.DnsSafeHost -notin @('github.com', 'api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com', 'www.wintun.net')) {
    throw 'Resource URL host is not an approved upstream.'
  }
}

function Receive-BoundedResource([string]$Url, [string]$Destination, [long]$MaxBytes, [string]$Sha256 = '', [long]$ExpectedBytes = 0) {
  if ($MaxBytes -le 0 -or ($Sha256 -and $Sha256 -notmatch '^[a-fA-F0-9]{64}$')) { throw 'Invalid resource limits/digest.' }
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $response = $null
  $stream = $null
  $output = $null
  try {
    for ($redirects = 0; $redirects -le 5; $redirects++) {
      Assert-ResourceUrl $Url
      $request = [Net.HttpWebRequest]::Create($Url)
      $request.AllowAutoRedirect = $false
      $request.Timeout = 30000
      $request.ReadWriteTimeout = 30000
      $request.UserAgent = 'VKarmani-resource-maintenance/1.0'
      $response = $request.GetResponse()
      $status = [int]$response.StatusCode
      if ($status -ge 300 -and $status -lt 400) {
        $next = [Uri]::new([Uri]$Url, [string]$response.Headers['Location'])
        $response.Close(); $response = $null
        $Url = $next.AbsoluteUri
        continue
      }
      if ($status -ne 200) { throw 'Resource HTTP status is not 200.' }
      break
    }
    if (-not $response -or [int]$response.StatusCode -ne 200) { throw 'Resource redirect limit exceeded.' }
    if ($response.ContentLength -gt $MaxBytes) { throw 'Resource content-length limit exceeded.' }
    $stream = $response.GetResponseStream()
    $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $buffer = New-Object byte[] 65536
    [long]$total = 0
    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $total += $count
      if ($total -gt $MaxBytes -or $timer.Elapsed.TotalSeconds -gt 120) { throw 'Resource byte/deadline limit exceeded.' }
      $output.Write($buffer, 0, $count)
    }
    $output.Flush($true); $output.Dispose(); $output = $null
    if ($total -eq 0 -or ($ExpectedBytes -gt 0 -and $total -ne $ExpectedBytes)) { throw 'Resource exact size mismatch.' }
    $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Sha256 -and $actual -ne $Sha256.ToLowerInvariant()) { throw 'Resource SHA256 mismatch.' }
    return [PSCustomObject]@{ size = $total; sha256 = $actual; source = $Url }
  } finally {
    if ($output) { $output.Dispose() }
    if ($stream) { $stream.Dispose() }
    if ($response) { $response.Close() }
  }
}

function Expand-SafeResourceArchive([string]$Archive, [string]$Destination) {
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
  $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
  try {
    if ($zip.Entries.Count -gt 100) { throw 'Archive entry limit exceeded.' }
    [long]$total = 0
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $zip.Entries) {
      $name = $entry.FullName
      $target = [IO.Path]::GetFullPath((Join-Path $Destination $name))
      $kind = (($entry.ExternalAttributes -shr 16) -band 61440)
      if ([IO.Path]::IsPathRooted($name) -or $name.Split('/') -contains '..' -or -not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or $name.Contains(':') -or $name.Contains('\') -or $kind -eq 40960 -or -not $seen.Add($target)) {
        throw 'Unsafe archive path, symlink, or duplicate entry.'
      }
      $total += $entry.Length
      if ($entry.Length -gt 80MB -or $total -gt 120MB) { throw 'Archive expanded size limit exceeded.' }
    }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($entry in $zip.Entries) {
      $target = [IO.Path]::GetFullPath((Join-Path $Destination $entry.FullName))
      if ($entry.FullName.EndsWith('/')) { [IO.Directory]::CreateDirectory($target) | Out-Null; continue }
      [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
      $inputStream = $entry.Open()
      $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $inputStream.CopyTo($output); $output.Flush($true) } finally { $output.Dispose(); $inputStream.Dispose() }
    }
  } finally { $zip.Dispose() }
}

function Assert-WindowsAmd64Pe([string]$Path) {
  $file = [IO.File]::OpenRead($Path)
  try {
    $reader = New-Object IO.BinaryReader($file)
    if ($file.Length -lt 256 -or $reader.ReadUInt16() -ne 23117) { throw 'Invalid Windows PE MZ header.' }
    $file.Position = 60
    $offset = $reader.ReadUInt32()
    if ($offset -lt 64 -or $offset + 26 -gt $file.Length) { throw 'Invalid Windows PE offset.' }
    $file.Position = $offset
    if ($reader.ReadUInt32() -ne 17744 -or $reader.ReadUInt16() -ne 34404) { throw 'Resource must be Windows amd64 PE.' }
    $file.Position = $offset + 24
    if ($reader.ReadUInt16() -ne 523) { throw 'Resource must be PE32+.' }
  } finally { $file.Dispose() }
}

function Assert-CoreBundle([string]$Directory) {
  $manifest = Get-Content -LiteralPath (Join-Path $Directory 'core-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  foreach ($name in @('xray.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat')) {
    $entries = @($manifest.files | Where-Object { $_.file -ceq $name })
    if ($entries.Count -ne 1) { throw "Missing/duplicate manifest resource: $name" }
    $entry = $entries[0]
    $path = Join-Path $Directory $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing resource: $name" }
    if ([long]$entry.size -le 0 -or (Get-Item -LiteralPath $path).Length -ne [long]$entry.size) { throw "Resource size mismatch: $name" }
    if ([string]$entry.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$entry.sha256) { throw "Resource digest mismatch: $name" }
  }
  Assert-WindowsAmd64Pe (Join-Path $Directory 'xray.exe')
  Assert-WindowsAmd64Pe (Join-Path $Directory 'wintun.dll')
}

function Publish-CoreBundle([string]$Stage, [string]$Destination) {
  $stagePath = [IO.Path]::GetFullPath($Stage)
  $destinationPath = [IO.Path]::GetFullPath($Destination)
  $parent = [IO.Path]::GetDirectoryName($destinationPath)
  if ([IO.Path]::GetDirectoryName($stagePath) -ne $parent -or [IO.Path]::GetFileName($stagePath) -notmatch '^\.windows-stage-[a-f0-9]{32}$' -or [IO.Path]::GetFileName($destinationPath) -ne 'windows') {
    throw 'Bundle publication requires an owned sibling stage and the windows destination.'
  }
  Assert-CoreBundle $stagePath
  $backup = Join-Path $parent ('.windows-backup-' + [Guid]::NewGuid().ToString('N'))
  $journal = Join-Path $parent '.windows-replacement.json'
  if (Test-Path -LiteralPath $journal) { throw 'Previous resource publication requires explicit recovery; no overwrite.' }
  $journalFile = [IO.File]::Open($journal, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{ destination = $destinationPath; stage = $stagePath; backup = $backup } | ConvertTo-Json))
    $journalFile.Write($bytes, 0, $bytes.Length); $journalFile.Flush($true)
  } finally { $journalFile.Dispose() }
  $moved = $false
  try {
    if (Test-Path -LiteralPath $destinationPath) { [IO.Directory]::Move($destinationPath, $backup); $moved = $true }
    [IO.Directory]::Move($stagePath, $destinationPath)
    Assert-CoreBundle $destinationPath
    Remove-Item -LiteralPath $journal
    # Keep the exact previous bundle for rollback; cleanup is an explicit owned-artifact step.
    return $backup
  } catch {
    if (-not (Test-Path -LiteralPath $destinationPath) -and $moved) { [IO.Directory]::Move($backup, $destinationPath) }
    throw
  }
}

Export-ModuleMember -Function Assert-ResourceUrl, Receive-BoundedResource, Expand-SafeResourceArchive, Assert-WindowsAmd64Pe, Assert-CoreBundle, Publish-CoreBundle
