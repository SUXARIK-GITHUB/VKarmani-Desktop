$ErrorActionPreference = 'Stop'

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$CoreDir = Join-Path $Root 'resources\core\windows'
$XrayPath = Join-Path $CoreDir 'xray.exe'

if (-not (Test-Path -LiteralPath $XrayPath -PathType Leaf)) {
  throw "xray.exe is missing: $XrayPath"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vkarmani-hy2-xray-test-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
$ConfigPath = Join-Path $TempDir 'hysteria2-xray-test.json'

try {
  $config = [ordered]@{
    log = [ordered]@{
      loglevel = 'warning'
    }
    dns = [ordered]@{
      servers = @('1.1.1.1', '8.8.8.8', 'localhost')
    }
    inbounds = @(
      [ordered]@{
        tag = 'socks-in'
        listen = '127.0.0.1'
        port = 10808
        protocol = 'socks'
        settings = [ordered]@{
          udp = $true
          auth = 'noauth'
        }
      }
    )
    outbounds = @(
      [ordered]@{
        tag = 'proxy'
        protocol = 'hysteria'
        settings = [ordered]@{
          version = 2
          address = 'hy2.example.com'
          port = 443
        }
        streamSettings = [ordered]@{
          network = 'hysteria'
          security = 'tls'
          tlsSettings = [ordered]@{
            serverName = 'hy2.example.com'
            fingerprint = 'chrome'
            alpn = @('h3')
          }
          hysteriaSettings = [ordered]@{
            version = 2
            auth = 'vkarmani-hy2-test-password'
          }
          udpmasks = @(
            [ordered]@{
              type = 'salamander'
              settings = [ordered]@{
                password = 'vkarmani-hy2-obfs-password'
              }
            }
          )
        }
      },
      [ordered]@{
        tag = 'direct'
        protocol = 'freedom'
        settings = [ordered]@{}
      },
      [ordered]@{
        tag = 'block'
        protocol = 'blackhole'
        settings = [ordered]@{}
      }
    )
  }

  $json = ($config | ConvertTo-Json -Depth 20) + "`n"
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($ConfigPath, $json, $utf8NoBom)

  Write-Host "[hy2-check] Running bundled Xray config test for Hysteria2 fixture..."
  $stdout = Join-Path $TempDir 'stdout.log'
  $stderr = Join-Path $TempDir 'stderr.log'
  $process = Start-Process -FilePath $XrayPath -ArgumentList @('run', '-test', '-config', $ConfigPath) -WorkingDirectory $CoreDir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $out = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue } else { '' }
  $err = if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue } else { '' }

  if ($process.ExitCode -ne 0) {
    throw "Bundled Xray rejected VKarmani Hysteria2 fixture. ExitCode=$($process.ExitCode)`nSTDOUT:`n$out`nSTDERR:`n$err"
  }

  Write-Host '[hy2-check] OK: bundled Xray accepts VKarmani Hysteria2 runtime schema.'
} finally {
  Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
