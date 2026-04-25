fn stop_existing_runtime(app: &AppHandle, state: &tauri::State<AppState>) -> Result<(), String> {
    let mut runtime_guard = state
        .runtime
        .lock()
        .map_err(|_| "Не удалось получить доступ к runtime состоянию.".to_string())?;

    if let Some(mut runtime) = runtime_guard.take() {
        let _ = append_runtime_event(app, "Останавливаем предыдущий Xray runtime.");
        let _ = runtime.child.kill();
        let status = runtime.child.wait().ok();

        if runtime.network_mode == "tun" {
            let _ = cleanup_tun_routes(
                runtime.tun_interface_name.as_deref().unwrap_or(TUN_INTERFACE_NAME),
                runtime.tun_server_ip.as_deref(),
            );
        }

        let _ = restore_saved_proxy_state(app, state, "runtime_stop");
        let _ = fs::remove_file(Path::new(&runtime.config_path));

        if let Some(code) = status.and_then(|item| item.code()) {
            if let Ok(mut exit_guard) = state.last_exit_code.lock() {
                *exit_guard = Some(code);
            }
        }
    }

    if let Ok(mut guard) = state.connected.lock() {
        *guard = false;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = None;
    }

    Ok(())
}


fn cleanup_application(app: &AppHandle, reason: &str) {
    let state = app.state::<AppState>();
    let _ = append_runtime_event(app, &format!("Запущен cleanup приложения: {reason}."));
    let _ = stop_existing_runtime(app, &state);
    let _ = restore_saved_proxy_state(app, &state, reason);
    let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, None);
    let _ = cleanup_runtime_config_files(app);
    refresh_tray_menu(app);
}

fn tcp_port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);

    addr.to_socket_addrs()
        .ok()
        .and_then(|mut values| values.next())
        .map(|socket| TcpStream::connect_timeout(&socket, timeout).is_ok())
        .unwrap_or(false)
}

fn ensure_runtime_ports_available() -> Result<(), String> {
    let mut busy_ports = Vec::new();

    if tcp_port_open("127.0.0.1", SOCKS_PORT, 350) {
        busy_ports.push(SOCKS_PORT);
    }

    if tcp_port_open("127.0.0.1", HTTP_PORT, 350) {
        busy_ports.push(HTTP_PORT);
    }

    if busy_ports.is_empty() {
        return Ok(());
    }

    Err(format!(
        "Локальные порты VKarmani уже заняты: {}. Закройте другой VPN/proxy-клиент или перезапустите VKarmani.",
        busy_ports
            .iter()
            .map(|port| format!("127.0.0.1:{port}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<String, String> {
    let mut command = Command::new("powershell");
    hide_child_console(&mut command);
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|error| format!("Не удалось запустить PowerShell: {error}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(target_os = "windows")]
fn run_powershell_with_env(script: &str, envs: &[(String, String)]) -> Result<String, String> {
    let mut command = Command::new("powershell");
    hide_child_console(&mut command);
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|error| format!("Не удалось запустить PowerShell: {error}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn proxy_status_from_registry_json(raw: &str, method: &str) -> Result<ProxyStatus, String> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|error| format!("Не удалось разобрать ответ PowerShell: {error}"))?;

    Ok(ProxyStatus {
        enabled: value.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        server: value
            .get("server")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        bypass: value
            .get("bypass")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        method: method.into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}

#[cfg(target_os = "windows")]
fn current_proxy_snapshot() -> Result<ProxyStatus, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$value = Get-ItemProperty -Path $key
[pscustomobject]@{
  enabled = [bool]($value.ProxyEnable -eq 1)
  server = [string]$value.ProxyServer
  bypass = [string]$value.ProxyOverride
} | ConvertTo-Json -Compress
"#;

    let raw = run_powershell(script)?;
    proxy_status_from_registry_json(&raw, "wininet-registry")
}

#[cfg(not(target_os = "windows"))]
fn current_proxy_snapshot() -> Result<ProxyStatus, String> {
    Ok(ProxyStatus {
        enabled: false,
        server: None,
        bypass: None,
        method: "mock".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}

#[cfg(target_os = "windows")]
fn apply_windows_proxy_snapshot(snapshot: &ProxyStatus) -> Result<ProxyStatus, String> {
    let proxy_enable = if snapshot.enabled { 1 } else { 0 };
    let proxy_server = snapshot.server.clone().unwrap_or_default();
    let proxy_bypass = snapshot.bypass.clone().unwrap_or_default();
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty -Path $key -Name ProxyEnable -Value {proxy_enable}
Set-ItemProperty -Path $key -Name ProxyServer -Value '{proxy_server}'
Set-ItemProperty -Path $key -Name ProxyOverride -Value '{proxy_bypass}'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WinInetNative {{
  [DllImport("wininet.dll", SetLastError=true)]
  public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}}
"@
[WinInetNative]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInetNative]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
"#,
        proxy_enable = proxy_enable,
        proxy_server = ps_quote(&proxy_server),
        proxy_bypass = ps_quote(&proxy_bypass),
    );
    run_powershell(&script)?;
    current_proxy_snapshot()
}

#[cfg(not(target_os = "windows"))]
fn apply_windows_proxy_snapshot(snapshot: &ProxyStatus) -> Result<ProxyStatus, String> {
    Ok(ProxyStatus {
        enabled: snapshot.enabled,
        server: snapshot.server.clone(),
        bypass: snapshot.bypass.clone(),
        method: "mock".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}

#[cfg(target_os = "windows")]
fn set_windows_proxy(enabled: bool) -> Result<ProxyStatus, String> {
    let proxy_enable = if enabled { 1 } else { 0 };
    let proxy_server = if enabled {
        format!("http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT}")
    } else {
        String::new()
    };

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty -Path $key -Name ProxyEnable -Value {proxy_enable}
Set-ItemProperty -Path $key -Name ProxyServer -Value '{proxy_server}'
Set-ItemProperty -Path $key -Name ProxyOverride -Value '{proxy_bypass}'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WinInetNative {{
  [DllImport("wininet.dll", SetLastError=true)]
  public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}}
"@
[WinInetNative]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInetNative]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
"#,
        proxy_enable = proxy_enable,
        proxy_server = proxy_server,
        proxy_bypass = PROXY_BYPASS,
    );

    run_powershell(&script)?;
    current_proxy_snapshot()
}

#[cfg(not(target_os = "windows"))]
fn set_windows_proxy(enabled: bool) -> Result<ProxyStatus, String> {
    Ok(ProxyStatus {
        enabled,
        server: if enabled {
            Some(format!("http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT}"))
        } else {
            None
        },
        bypass: if enabled {
            Some(PROXY_BYPASS.to_string())
        } else {
            None
        },
        method: "mock".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}


fn proxy_snapshot_points_to_runtime(snapshot: &ProxyStatus) -> bool {
    snapshot.enabled
        && snapshot
            .server
            .as_deref()
            .map(|server| server.contains(&format!("127.0.0.1:{HTTP_PORT}")))
            .unwrap_or(false)
}

fn restore_saved_proxy_state(app: &AppHandle, state: &tauri::State<AppState>, reason: &str) -> Result<Option<ProxyStatus>, String> {
    let previous = state
        .previous_proxy
        .lock()
        .ok()
        .and_then(|mut value| value.take());

    let restored = if let Some(snapshot) = previous {
        Some(apply_windows_proxy_snapshot(&snapshot)?)
    } else {
        let current = current_proxy_snapshot()?;
        if proxy_snapshot_points_to_runtime(&current) {
            Some(set_windows_proxy(false)?)
        } else {
            None
        }
    };

    if let Some(status) = &restored {
        let _ = append_runtime_event(
            app,
            &format!(
                "Windows system proxy восстановлен ({reason}) | enabled={} | server={} | bypass={}",
                status.enabled,
                status.server.clone().unwrap_or_else(|| "—".into()),
                status.bypass.clone().unwrap_or_else(|| "—".into())
            ),
        );
    }

    Ok(restored)
}


#[cfg(target_os = "windows")]
fn is_process_elevated() -> Result<bool, String> {
    let script = r#"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'true' } else { 'false' }
"#;

    let raw = run_powershell(script)?;
    Ok(raw.trim().eq_ignore_ascii_case("true"))
}

#[cfg(not(target_os = "windows"))]
fn is_process_elevated() -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn sync_runtime_liveness(app: &AppHandle, state: &tauri::State<AppState>) {
    let mut exit_code: Option<Option<i32>> = None;

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        if let Some(runtime) = runtime_guard.as_mut() {
            match runtime.child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = Some(status.code());
                    let finished_runtime = runtime_guard.take();
                    if let Some(runtime) = finished_runtime {
                        if runtime.network_mode == "tun" {
                            let _ = cleanup_tun_routes(
                                runtime.tun_interface_name.as_deref().unwrap_or(TUN_INTERFACE_NAME),
                                runtime.tun_server_ip.as_deref(),
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = append_runtime_event(
                        app,
                        &format!("Не удалось проверить состояние Xray-core: {error}"),
                    );
                }
            }
        }
    }

    if let Some(code) = exit_code {
        if let Ok(mut exit_guard) = state.last_exit_code.lock() {
            *exit_guard = code;
        }

        if let Ok(mut guard) = state.connected.lock() {
            *guard = false;
        }

        if let Ok(mut guard) = state.active_server_label.lock() {
            *guard = None;
        }

        let _ = append_runtime_event(
            app,
            &format!("Xray-core завершился во время работы. Exit code: {:?}", code),
        );
        let _ = restore_saved_proxy_state(app, state, "xray_exit");
        let _ = app.emit("vkarmani://native-disconnect", "stopped");
        refresh_tray_menu(app);
    }
}
