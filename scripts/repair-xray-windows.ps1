param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectDir
)

$ErrorActionPreference = 'Stop'
$CoreDir = Join-Path $ProjectDir 'resources\core\windows'
$XrayPath = Join-Path $CoreDir 'xray.exe'
$ManifestPath = Join-Path $CoreDir 'core-manifest.json'
$OfficialVersion = 'v26.3.27'
$OfficialZipUrl = "https://github.com/XTLS/Xray-core/releases/download/$OfficialVersion/Xray-windows-64.zip"

function Test-WindowsX64Exe {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }

    $fs = [IO.File]::OpenRead($Path)
    try {
        if ($fs.Length -lt 256) { return $false }
        $br = [IO.BinaryReader]::new($fs)
        if ($br.ReadByte() -ne 0x4D -or $br.ReadByte() -ne 0x5A) { return $false }
        $fs.Position = 0x3C
        $pe = $br.ReadInt32()
        if ($pe -lt 0 -or ($pe + 6) -ge $fs.Length) { return $false }
        $fs.Position = $pe
        if ($br.ReadByte() -ne 0x50 -or $br.ReadByte() -ne 0x45 -or $br.ReadByte() -ne 0 -or $br.ReadByte() -ne 0) { return $false }
        $machine = $br.ReadUInt16()
        return ($machine -eq 0x8664)
    }
    finally {
        $fs.Dispose()
    }
}

function Test-XrayLaunch {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-WindowsX64Exe -Path $Path)) { return $false }

    try {
        $process = Start-Process -FilePath $Path -ArgumentList 'version' -NoNewWindow -PassThru -Wait -RedirectStandardOutput ([IO.Path]::GetTempFileName()) -RedirectStandardError ([IO.Path]::GetTempFileName())
        return ($process.ExitCode -eq 0)
    }
    catch {
        Write-Host "[WARN] xray.exe launch test failed: $($_.Exception.Message)"
        return $false
    }
}

function Write-Utf8NoBomFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Update-CoreManifest {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $files = @()
    foreach ($name in @('xray.exe', 'geoip.dat', 'geosite.dat', 'wintun.dll')) {
        $path = Join-Path $Directory $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
            $files += [ordered]@{
                file = $name
                sha256 = $hash
                size = [int64]$item.Length
            }
        }
    }

    $manifest = [ordered]@{
        version = '0.13.20'
        generatedFor = 'VKarmani Desktop bundled core artifacts'
        files = $files
    }
    $json = $manifest | ConvertTo-Json -Depth 5
    Write-Utf8NoBomFile -Path $ManifestPath -Content ($json + [Environment]::NewLine)
}

New-Item -ItemType Directory -Force -Path $CoreDir | Out-Null

if (Test-XrayLaunch -Path $XrayPath) {
    Write-Host '[INFO] Xray-core launch check passed.'
    Update-CoreManifest -Directory $CoreDir
    exit 0
}

Write-Host '[WARN] Bundled xray.exe is missing, corrupted, blocked, or not launchable.'
Write-Host "[INFO] Downloading official Xray-core $OfficialVersion for Windows x64..."

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("vkarmani-xray-repair-" + [Guid]::NewGuid().ToString('N'))
$zipPath = Join-Path $tempRoot 'Xray-windows-64.zip'
$extractDir = Join-Path $tempRoot 'extract'

try {
    New-Item -ItemType Directory -Force -Path $tempRoot, $extractDir | Out-Null
    Invoke-WebRequest -Uri $OfficialZipUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

    $downloadedXray = Get-ChildItem -LiteralPath $extractDir -Recurse -Filter 'xray.exe' | Select-Object -First 1
    if (-not $downloadedXray) {
        throw 'Official Xray archive does not contain xray.exe.'
    }

    Copy-Item -LiteralPath $downloadedXray.FullName -Destination $XrayPath -Force

    foreach ($sidecar in @('geoip.dat', 'geosite.dat')) {
        $downloadedSidecar = Get-ChildItem -LiteralPath $extractDir -Recurse -Filter $sidecar | Select-Object -First 1
        if ($downloadedSidecar) {
            Copy-Item -LiteralPath $downloadedSidecar.FullName -Destination (Join-Path $CoreDir $sidecar) -Force
        }
    }

    if (-not (Test-XrayLaunch -Path $XrayPath)) {
        throw 'Downloaded xray.exe still cannot be launched as Windows x64 executable.'
    }

    Update-CoreManifest -Directory $CoreDir
    Write-Host '[INFO] Xray-core repaired successfully.'
    exit 0
}
catch {
    Write-Host "[ERROR] Could not repair Xray-core automatically: $($_.Exception.Message)"
    Write-Host '[ERROR] Manual fallback: download Xray-windows-64.zip from official XTLS/Xray-core releases, extract xray.exe into resources\core\windows, then run START_VKarmani.bat again.'
    exit 1
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
