fn terminate_child_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let _ = child.kill();
    let started_at = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if started_at.elapsed() >= timeout {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(35));
            }
            Err(_) => return None,
        }
    }
}

fn stop_existing_runtime(app: &AppHandle, state: &tauri::State<AppState>) -> Result<(), String> {
    let runtime_to_stop = {
        let mut runtime_guard = state
            .runtime
            .lock()
            .map_err(|_| "Не удалось получить доступ к runtime состоянию.".to_string())?;
        runtime_guard.take()
    };

    if let Some(mut runtime) = runtime_to_stop {
        let _ = append_runtime_event(app, "Останавливаем предыдущий Xray runtime.");
        let status = terminate_child_with_timeout(&mut runtime.child, Duration::from_secs(3));

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

#[cfg(target_os = "windows")]
fn escape_powershell_single_quoted(value: &str) -> String {
    value.replace("'", "''")
}

#[cfg(target_os = "windows")]
fn stop_orphan_xray_processes(app: &AppHandle, core_path: &Path) {
    let target = escape_powershell_single_quoted(&core_path.to_string_lossy());
    let script = format!(
        r#"& {{ $target = '{}'; Get-CimInstance Win32_Process -Filter "name = 'xray.exe'" | Where-Object {{ $_.ExecutablePath -and ($_.ExecutablePath -ieq $target) }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Write-Output $_.ProcessId }} }}"#,
        target
    );

    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script]);

    match run_command_with_timeout(command, Duration::from_secs(4), "stop orphan xray") {
        Ok(output) => {
            let cleaned = output.trim();
            if !cleaned.is_empty() {
                let _ = append_runtime_event(
                    app,
                    &format!("Перед новым стартом остановлены старые процессы xray.exe: {cleaned}."),
                );
            }
        }
        Err(error) => {
            let _ = append_runtime_event(
                app,
                &format!("Не удалось проверить/остановить старые процессы xray.exe: {error}"),
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn stop_orphan_xray_processes(_app: &AppHandle, _core_path: &Path) {}


fn cleanup_application(app: &AppHandle, reason: &str) {
    let state = app.state::<AppState>();
    let _ = append_runtime_event(app, &format!("Запущен cleanup приложения: {reason}."));
    let _ = stop_existing_runtime(app, &state);
    let _ = restore_saved_proxy_state(app, &state, reason);
    let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, None);
    let _ = cleanup_runtime_config_files(app);
    refresh_tray_menu(app);
}

fn normalize_socket_host(host: &str) -> String {
    host.trim().trim_matches('[').trim_matches(']').to_string()
}

fn format_endpoint_for_display(host: &str, port: u16) -> String {
    let normalized = normalize_socket_host(host);
    if normalized.contains(':') {
        format!("[{normalized}]:{port}")
    } else {
        format!("{normalized}:{port}")
    }
}

fn resolve_socket_addresses(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    let normalized = normalize_socket_host(host);
    if normalized.is_empty() {
        return Err("Host пустой.".into());
    }

    let mut addresses = (normalized.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| format!("Не удалось разрешить адрес {normalized}:{port}: {error}"))?
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        return Err(format!("Не удалось получить IP адрес для {normalized}:{port}."));
    }

    // На многих клиентских ПК IPv6 отключён или работает нестабильно. Сначала
    // пробуем IPv4, чтобы TCP-проверки, proxy/TUN readiness и ping не ждали
    // IPv6 timeout при наличии нормальной A-записи.
    addresses.sort_by_key(|address| if address.is_ipv4() { 0 } else { 1 });

    Ok(addresses)
}

fn tcp_port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms);

    resolve_socket_addresses(host, port)
        .map(|addresses| {
            addresses
                .iter()
                .any(|socket| TcpStream::connect_timeout(socket, timeout).is_ok())
        })
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

    if tcp_port_open("127.0.0.1", XRAY_API_PORT, 350) {
        busy_ports.push(XRAY_API_PORT);
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
const POWERSHELL_COMMAND_TIMEOUT: Duration = Duration::from_secs(12);

#[cfg(target_os = "windows")]
fn run_powershell_command(mut command: Command, context: &str) -> Result<String, String> {
    hide_child_console(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("Не удалось запустить PowerShell ({context}): {error}"))?;
    let started_at = Instant::now();

    loop {
        if child
            .try_wait()
            .map_err(|error| format!("Не удалось проверить состояние PowerShell ({context}): {error}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|error| format!("Не удалось прочитать ответ PowerShell ({context}): {error}"))?;

            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Err(if stderr.is_empty() { stdout } else { stderr });
        }

        if started_at.elapsed() >= POWERSHELL_COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "PowerShell операция {context} зависла дольше {} секунд и была остановлена.",
                POWERSHELL_COMMAND_TIMEOUT.as_secs()
            ));
        }

        std::thread::sleep(Duration::from_millis(35));
    }
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<String, String> {
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    run_powershell_command(command, "script")
}

fn run_command_with_timeout(mut command: Command, timeout: Duration, context: &str) -> Result<String, String> {
    hide_child_console(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("Не удалось запустить команду ({context}): {error}"))?;
    let started_at = Instant::now();

    loop {
        if child
            .try_wait()
            .map_err(|error| format!("Не удалось проверить состояние команды ({context}): {error}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|error| format!("Не удалось прочитать ответ команды ({context}): {error}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

            if output.status.success() {
                return Ok(stdout);
            }

            return Err(if stderr.is_empty() { stdout } else { stderr });
        }

        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "Команда {context} зависла дольше {} секунд и была остановлена.",
                timeout.as_secs()
            ));
        }

        std::thread::sleep(Duration::from_millis(35));
    }
}

#[cfg(target_os = "windows")]
fn run_powershell_with_env(script: &str, envs: &[(String, String)]) -> Result<String, String> {
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (key, value) in envs {
        command.env(key, value);
    }
    run_powershell_command(command, "script-with-env")
}

#[cfg(test)]
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
const INTERNET_SETTINGS_REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(target_os = "windows")]
fn run_reg_command(args: &[&str], context: &str) -> Result<String, String> {
    let mut command = Command::new("reg");
    command.args(args);
    run_command_with_timeout(command, Duration::from_secs(4), context)
}

#[cfg(target_os = "windows")]
fn parse_reg_value(raw: &str, value_name: &str) -> Option<String> {
    raw.lines()
        .map(str::trim)
        .find(|line| line.starts_with(value_name))
        .and_then(|line| {
            if let Some(index) = line.find("REG_DWORD") {
                return Some(line[index + "REG_DWORD".len()..].trim().to_string());
            }
            if let Some(index) = line.find("REG_SZ") {
                return Some(line[index + "REG_SZ".len()..].trim().to_string());
            }
            None
        })
}

#[cfg(target_os = "windows")]
fn read_reg_value(value_name: &str) -> Option<String> {
    run_reg_command(&["query", INTERNET_SETTINGS_REG_KEY, "/v", value_name], &format!("reg query {value_name}"))
        .ok()
        .and_then(|raw| parse_reg_value(&raw, value_name))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "windows")]
fn write_reg_dword(value_name: &str, value: u32) -> Result<(), String> {
    run_reg_command(
        &["add", INTERNET_SETTINGS_REG_KEY, "/v", value_name, "/t", "REG_DWORD", "/d", &value.to_string(), "/f"],
        &format!("reg add {value_name}"),
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_reg_string(value_name: &str, value: &str) -> Result<(), String> {
    run_reg_command(
        &["add", INTERNET_SETTINGS_REG_KEY, "/v", value_name, "/t", "REG_SZ", "/d", value, "/f"],
        &format!("reg add {value_name}"),
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn notify_wininet_proxy_changed() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    // Registry writes alone are not enough: many Windows apps cache WinINet
    // proxy settings. Notify the OS immediately so browsers/launchers pick up
    // Xray proxy enable/restore without requiring an app restart.
    unsafe {
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(target_os = "windows")]
fn current_proxy_snapshot() -> Result<ProxyStatus, String> {
    let enabled_raw = read_reg_value("ProxyEnable").unwrap_or_else(|| "0x0".to_string());
    let enabled = u32::from_str_radix(enabled_raw.trim_start_matches("0x"), 16).unwrap_or(0) == 1
        || enabled_raw.trim() == "1";

    Ok(ProxyStatus {
        enabled,
        server: read_reg_value("ProxyServer"),
        bypass: read_reg_value("ProxyOverride"),
        method: "wininet-registry".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
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

fn proxy_backup_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("system-proxy-backup.json"))
}

fn save_proxy_backup_snapshot(app: &AppHandle, snapshot: &ProxyStatus) -> Result<(), String> {
    let path = proxy_backup_path(app)?;
    let payload = serde_json::to_string_pretty(snapshot)
        .map_err(|error| format!("Не удалось сериализовать backup системного proxy: {error}"))?;
    fs::write(path, payload)
        .map_err(|error| format!("Не удалось сохранить backup системного proxy: {error}"))
}

fn load_proxy_backup_snapshot(app: &AppHandle) -> Result<Option<ProxyStatus>, String> {
    let path = proxy_backup_path(app)?;
    if !path.exists() {
        return Ok(None);
    }

    let payload = fs::read_to_string(&path)
        .map_err(|error| format!("Не удалось прочитать backup системного proxy: {error}"))?;
    let snapshot = serde_json::from_str::<ProxyStatus>(&payload)
        .map_err(|error| format!("Не удалось разобрать backup системного proxy: {error}"))?;
    Ok(Some(snapshot))
}

fn clear_proxy_backup_snapshot(app: &AppHandle) {
    if let Ok(path) = proxy_backup_path(app) {
        let _ = fs::remove_file(path);
    }
}

fn capture_previous_proxy_state(app: &AppHandle, state: &tauri::State<AppState>) -> Result<(), String> {
    if let Ok(mut previous_guard) = state.previous_proxy.lock() {
        if previous_guard.is_some() {
            return Ok(());
        }

        if let Some(snapshot) = load_proxy_backup_snapshot(app).ok().flatten() {
            *previous_guard = Some(snapshot);
            return Ok(());
        }

        let snapshot = current_proxy_snapshot()?;
        *previous_guard = Some(snapshot.clone());
        return save_proxy_backup_snapshot(app, &snapshot);
    }

    if load_proxy_backup_snapshot(app).ok().flatten().is_some() {
        return Ok(());
    }

    let snapshot = current_proxy_snapshot()?;
    save_proxy_backup_snapshot(app, &snapshot)
}

fn take_saved_proxy_state(app: &AppHandle, state: &tauri::State<AppState>) -> Option<ProxyStatus> {
    state
        .previous_proxy
        .lock()
        .ok()
        .and_then(|mut value| value.take())
        .or_else(|| load_proxy_backup_snapshot(app).ok().flatten())
}

#[cfg(target_os = "windows")]
fn apply_windows_proxy_snapshot(snapshot: &ProxyStatus) -> Result<ProxyStatus, String> {
    let proxy_enable = if snapshot.enabled { 1 } else { 0 };
    let proxy_server = snapshot.server.clone().unwrap_or_default();
    let proxy_bypass = snapshot.bypass.clone().unwrap_or_default();

    write_reg_dword("ProxyEnable", proxy_enable)?;
    write_reg_string("ProxyServer", &proxy_server)?;
    write_reg_string("ProxyOverride", &proxy_bypass)?;
    notify_wininet_proxy_changed();
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
    let proxy_bypass = if enabled { PROXY_BYPASS } else { "" };

    write_reg_dword("ProxyEnable", proxy_enable)?;
    write_reg_string("ProxyServer", &proxy_server)?;
    write_reg_string("ProxyOverride", proxy_bypass)?;
    notify_wininet_proxy_changed();
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
    let previous = take_saved_proxy_state(app, state);

    let restored = if let Some(snapshot) = previous {
        let status = apply_windows_proxy_snapshot(&snapshot)?;
        clear_proxy_backup_snapshot(app);
        Some(status)
    } else {
        let current = current_proxy_snapshot()?;
        if proxy_snapshot_points_to_runtime(&current) {
            let status = set_windows_proxy(false)?;
            clear_proxy_backup_snapshot(app);
            Some(status)
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

fn recover_orphaned_system_proxy(app: &AppHandle, state: &tauri::State<AppState>, reason: &str) -> Result<Option<ProxyStatus>, String> {
    let current = current_proxy_snapshot()?;
    if !proxy_snapshot_points_to_runtime(&current) {
        return Ok(None);
    }

    let restored = restore_saved_proxy_state(app, state, reason)?;
    if restored.is_some() {
        let _ = append_runtime_event(
            app,
            "На старте найден proxy VKarmani без активного runtime. Настройки восстановлены из backup/безопасно отключены.",
        );
    }

    Ok(restored)
}


#[cfg(target_os = "windows")]
fn is_process_elevated() -> Result<bool, String> {
    // `fltmc` exits successfully only in an elevated process. It is much lighter than
    // spinning up PowerShell just to ask WindowsPrincipal for the admin role.
    let mut command = Command::new("fltmc");
    hide_child_console(&mut command);
    let output = command.output().map_err(|error| format!("Не удалось проверить права администратора: {error}"))?;
    Ok(output.status.success())
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
    let mut finished_runtime: Option<ManagedCore> = None;

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        if let Some(runtime) = runtime_guard.as_mut() {
            match runtime.child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = Some(status.code());
                    finished_runtime = runtime_guard.take();
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

    if let Some(runtime) = finished_runtime {
        if runtime.network_mode == "tun" {
            let _ = cleanup_tun_routes(
                runtime.tun_interface_name.as_deref().unwrap_or(TUN_INTERFACE_NAME),
                runtime.tun_server_ip.as_deref(),
            );
        }
        let _ = fs::remove_file(Path::new(&runtime.config_path));
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

fn start_runtime_watchdog(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        let state = app.state::<AppState>();
        sync_runtime_liveness(&app, &state);
    });
}
