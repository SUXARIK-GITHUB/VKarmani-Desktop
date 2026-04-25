#[tauri::command]
fn write_interface_log(message: String, details: Option<String>, app: AppHandle) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_interface_event(&app, &line)
}

#[tauri::command]
fn write_routing_log(message: String, details: Option<String>, app: AppHandle) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_runtime_event(&app, &line)
}

#[tauri::command]
fn public_ip_snapshot(mode: Option<String>) -> Result<String, String> {
    let normalized_mode = mode.unwrap_or_else(|| "direct".to_string()).to_lowercase();

    if normalized_mode == "runtime" {
        if !tcp_port_open("127.0.0.1", HTTP_PORT, 1200) {
            return Err(format!("HTTP inbound 127.0.0.1:{HTTP_PORT} не отвечает. Сначала запустите runtime."));
        }

        let client = build_http_client(Some(&format!("http://127.0.0.1:{HTTP_PORT}")), Duration::from_secs(8))?;
        return fetch_public_ip(&client);
    }

    let client = build_http_client(None, Duration::from_secs(4))?;
    fetch_public_ip(&client)
}

fn secure_access_key_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir).map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("access-key.dpapi"))
}

#[cfg(target_os = "windows")]
fn encrypt_access_key(value: &str) -> Result<String, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$plain = [Environment]::GetEnvironmentVariable('VKARMANI_ACCESS_KEY_PLAINTEXT', 'Process')
$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Convert]::ToBase64String($encrypted)
"#;
    run_powershell_with_env(script, &[("VKARMANI_ACCESS_KEY_PLAINTEXT".to_string(), value.to_string())])
}

#[cfg(target_os = "windows")]
fn decrypt_access_key(value: &str) -> Result<String, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$blob = [Environment]::GetEnvironmentVariable('VKARMANI_ACCESS_KEY_BLOB', 'Process')
$encrypted = [Convert]::FromBase64String($blob)
$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($bytes)
"#;
    run_powershell_with_env(script, &[("VKARMANI_ACCESS_KEY_BLOB".to_string(), value.to_string())])
}

#[cfg(not(target_os = "windows"))]
fn encrypt_access_key(value: &str) -> Result<String, String> {
    Ok(value.to_string())
}

#[cfg(not(target_os = "windows"))]
fn decrypt_access_key(value: &str) -> Result<String, String> {
    Ok(value.to_string())
}

#[tauri::command]
fn save_access_key_secure(value: String, app: AppHandle) -> Result<(), String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return clear_access_key_secure(app);
    }
    let encrypted = encrypt_access_key(normalized)?;
    fs::write(secure_access_key_path(&app)?, encrypted)
        .map_err(|error| format!("Не удалось сохранить ключ доступа в защищённое хранилище: {error}"))
}

#[tauri::command]
fn load_access_key_secure(app: AppHandle) -> Result<Option<String>, String> {
    let path = secure_access_key_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    let encrypted = fs::read_to_string(path)
        .map_err(|error| format!("Не удалось прочитать защищённый ключ доступа: {error}"))?;
    let value = decrypt_access_key(encrypted.trim())?;
    Ok(Some(value))
}

#[tauri::command]
fn clear_access_key_secure(app: AppHandle) -> Result<(), String> {
    let path = secure_access_key_path(&app)?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| format!("Не удалось удалить сохранённый ключ доступа: {error}"))?;
    }
    Ok(())
}



#[tauri::command]
fn bootstrap_info() -> BootstrapInfo {
    BootstrapInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
    }
}


#[tauri::command]
fn set_session_authorized(authorized: bool, state: tauri::State<AppState>, app: AppHandle) -> Result<bool, String> {
    if let Ok(mut guard) = state.session_authorized.lock() {
        *guard = authorized;
    }

    let _ = append_interface_event(
        &app,
        if authorized {
            "Сессия ЛК активна: обновляем меню трея."
        } else {
            "Сессия ЛК завершена: обновляем меню трея."
        },
    );
    refresh_tray_menu(&app);
    Ok(authorized)
}

#[tauri::command]
fn runtime_status(app: AppHandle, state: tauri::State<AppState>) -> RuntimeStatus {
    build_runtime_status(&app, state)
}

#[tauri::command]
fn request_connect(
    server_id: String,
    server_label: String,
    runtime_template: RuntimeTemplate,
    network_mode: Option<String>,
    split_tunnel_entries: Option<Vec<SplitTunnelEntryPayload>>,
    state: tauri::State<AppState>,
    app: AppHandle,
) -> Result<RuntimeStatus, String> {
    if runtime_template.family.to_lowercase() != "xray" {
        return Err("Сейчас поддерживается только Xray runtime family.".into());
    }

    let core_path = resolve_core_path(&app)
        .ok_or_else(|| core_not_found_message(&app))?;
    ensure_core_launchable(&core_path)?;

    let normalized_network_mode = match network_mode
        .unwrap_or_else(|| "proxy".to_string())
        .to_lowercase()
        .as_str()
    {
        "tun" => "tun".to_string(),
        _ => "proxy".to_string(),
    };

    let (outbound_host, outbound_port) = extract_outbound_address_and_port(&runtime_template);
    let outbound_ip = outbound_host
        .as_deref()
        .and_then(|host| resolve_ipv4_address(host, outbound_port));
    let send_through_ip = if normalized_network_mode == "tun" {
        detect_primary_ipv4_address()
    } else {
        None
    };

    #[cfg(target_os = "windows")]
    if normalized_network_mode == "tun" && !is_process_elevated()? {
        return Err("TUN режим требует запуска VKarmani с правами администратора, иначе Windows не даст создать маршруты. Откройте настройки клиента и включите запуск от администратора или перезапустите приложение вручную от имени администратора.".into());
    }

    if normalized_network_mode == "tun" && send_through_ip.is_none() {
        return Err("Не удалось определить локальный IPv4 адрес активного сетевого адаптера для TUN режима. Подключитесь к сети без VPN/виртуального адаптера и попробуйте снова.".into());
    }

    stop_existing_runtime(&app, &state)?;
    ensure_runtime_ports_available()?;

    let output_dir = runtime_output_dir(&app)?;
    let _ = cleanup_runtime_config_files(&app);
    let config_path = output_dir.join(format!("xray-config-{}-{}.json", std::process::id(), unix_now_string()));
    let active_split_tunnel_entries = split_tunnel_entries.unwrap_or_default();
    let runtime_trace_path = runtime_log_path(&app)?;
    let _ = fs::write(&runtime_trace_path, "");
    let log_path = runtime_trace_path.clone();

    let (config, split_tunnel_plan) = build_xray_config(
        &runtime_template,
        &normalized_network_mode,
        send_through_ip.as_deref(),
        &active_split_tunnel_entries,
        Some(runtime_trace_path.as_path()),
    );
    let config_text = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Не удалось сериализовать config: {error}"))?;
    fs::write(&config_path, config_text).map_err(|error| format!("Не удалось записать config: {error}"))?;

    if normalized_network_mode == "tun" {
        let core_dir = core_path.parent().map(|value| value.to_path_buf());
        let geoip_exists = core_dir
            .as_ref()
            .map(|dir| dir.join("geoip.dat").exists())
            .unwrap_or(false);
        let geosite_exists = core_dir
            .as_ref()
            .map(|dir| dir.join("geosite.dat").exists())
            .unwrap_or(false);
        let wintun_status = core_dir
            .as_ref()
            .map(|dir| {
                let path = dir.join("wintun.dll");
                if !path.exists() {
                    "нет файла".to_string()
                } else {
                    validate_pe_binary(&path, "wintun.dll").map(|_| "ok".to_string()).unwrap_or_else(|error| error)
                }
            })
            .unwrap_or_else(|| "не удалось определить папку core".to_string());
        let wintun_exists = wintun_status == "ok";
        let _ = append_runtime_event(
            &app,
            &format!(
                "TUN diagnostics: core={} | config={} | runtimeLog={} | geoip.dat={} | geosite.dat={} | wintun.dll={} | outboundHost={} | outboundIp={} | sendThrough={}",
                core_path.display(),
                config_path.display(),
                log_path.display(),
                geoip_exists,
                geosite_exists,
                wintun_status,
                outbound_host.as_deref().unwrap_or("—"),
                outbound_ip.as_deref().unwrap_or("—"),
                send_through_ip.as_deref().unwrap_or("—")
            ),
        );

        if !wintun_exists {
            return Err(format!(
                "TUN режим не может стартовать: рядом с xray.exe отсутствует или повреждён wintun.dll ({wintun_status}). Положите официальный amd64 wintun.dll в {} и повторите подключение.",
                core_dir
                    .as_ref()
                    .map(|dir| dir.display().to_string())
                    .unwrap_or_else(|| "resources/core/windows".to_string())
            ));
        }
    }

    append_runtime_event(
        &app,
        &format!(
            "Запуск Xray runtime для {server_label} · mode={} · protocol={} · remarks={}",
            normalized_network_mode,
            runtime_template.protocol,
            runtime_template.remarks.unwrap_or_else(|| "—".into())
        ),
    )?;

    if normalized_network_mode == "tun" {
        if split_tunnel_plan.process_matches.is_empty() {
            let _ = append_runtime_event(
                &app,
                "TUN selective mode: список программ пуст, поэтому невыбранный трафик будет обходить VPN напрямую.",
            );
        } else {
            let _ = append_runtime_event(
                &app,
                &format!(
                    "TUN selective mode: {} app rule(s), {} service rule(s), total process matches {}.",
                    split_tunnel_plan.resolved_apps,
                    split_tunnel_plan.resolved_services,
                    split_tunnel_plan.process_matches.len()
                ),
            );
        }

        for note in &split_tunnel_plan.skipped_notes {
            let _ = append_runtime_event(&app, note);
        }
    }

    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("Не удалось открыть stdout log: {error}"))?;
    let stderr_file = stdout_file
        .try_clone()
        .map_err(|error| format!("Не удалось дублировать stderr log: {error}"))?;

    let core_working_dir = core_path.parent().ok_or_else(|| {
        "Не удалось определить рабочую папку Xray-core для запуска runtime.".to_string()
    })?;

    let mut command = Command::new(&core_path);
    command
        .current_dir(core_working_dir)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    hide_child_console(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format_xray_spawn_error(&error, &core_path))?;

    std::thread::sleep(Duration::from_millis(350));
    if let Some(status) = child
        .try_wait()
        .map_err(|error| format!("Не удалось проверить статус Xray-core: {error}"))?
    {
        let code = status.code();
        if let Ok(mut exit_guard) = state.last_exit_code.lock() {
            *exit_guard = code;
        }
        let log_excerpt = read_runtime_log_excerpt(&log_path, 8);
        let joined_excerpt = log_excerpt.join(" | ");
        let _ = append_runtime_event(
            &app,
            &format!("Xray-core завершился сразу после старта. Exit code: {:?}", code),
        );

        if joined_excerpt.to_ascii_lowercase().contains("wintun.dll") {
            return Err(format!(
                "Xray-core не смог запустить TUN: отсутствует или не загружается wintun.dll рядом с xray.exe. Проверьте {}.",
                core_working_dir.display()
            ));
        }

        if !joined_excerpt.is_empty() {
            return Err(format!(
                "Xray-core завершился сразу после запуска. Exit code: {:?}. Последние строки xray-runtime.log: {}",
                code,
                joined_excerpt
            ));
        }

        return Err(format!(
            "Xray-core завершился сразу после запуска. Exit code: {:?}. Проверьте xray-runtime.log.",
            code
        ));
    }

    if normalized_network_mode == "tun" {
        configure_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref()).map_err(|error| {
            let _ = child.kill();
            let _ = child.wait();
            format!("Не удалось подготовить Windows-маршруты для TUN режима: {error}")
        })?;
        let _ = append_runtime_event(&app, "TUN маршруты применены для текущего сеанса.");
    }

    if let Ok(mut guard) = state.connected.lock() {
        *guard = true;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = Some(server_label.clone());
    }

    if let Ok(mut exit_guard) = state.last_exit_code.lock() {
        *exit_guard = None;
    }

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        *runtime_guard = Some(ManagedCore {
            child,
            core_path: core_path.to_string_lossy().to_string(),
            config_path: config_path.to_string_lossy().to_string(),
            log_path: log_path.to_string_lossy().to_string(),
            server_id: server_id.clone(),
            started_at: unix_now_string(),
            network_mode: normalized_network_mode.clone(),
            tun_interface_name: if normalized_network_mode == "tun" {
                Some(TUN_INTERFACE_NAME.to_string())
            } else {
                None
            },
            tun_server_ip: if normalized_network_mode == "tun" {
                outbound_ip.clone()
            } else {
                None
            },
        });
    }

    let _ = app.emit("vkarmani://native-connect", server_id);
    let _ = app.emit("vkarmani://native-status", server_label);
    refresh_tray_menu(&app);

    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
fn request_disconnect(state: tauri::State<AppState>, app: AppHandle) -> Result<RuntimeStatus, String> {
    stop_existing_runtime(&app, &state)?;

    if let Ok(mut guard) = state.connected.lock() {
        *guard = false;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = None;
    }

    let _ = append_runtime_event(&app, "Xray runtime остановлен пользователем.");
    let _ = app.emit("vkarmani://native-disconnect", "idle");
    refresh_tray_menu(&app);
    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
fn cache_profile_sync(profile_count: usize, source: String, state: tauri::State<AppState>, app: AppHandle) {
    if let Ok(mut guard) = state.profile_count.lock() {
        *guard = profile_count;
    }

    if let Ok(mut guard) = state.last_sync_source.lock() {
        *guard = Some(source.clone());
    }

    let _ = append_interface_event(
        &app,
        &format!("Кэш профиля обновлён. Профилей: {profile_count} | источник: {source}"),
    );
}

#[tauri::command]
fn request_show(app: AppHandle) {
    let _ = append_interface_event(&app, "Окно приложения раскрыто пользователем.");
    reveal_main_window(&app);
}

#[tauri::command]
fn window_minimize(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно свёрнуто.");
    window.minimize().map_err(|error| format!("Не удалось свернуть окно: {error}"))
}

#[tauri::command]
fn window_toggle_maximize(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let is_maximized = window
        .is_maximized()
        .map_err(|error| format!("Не удалось прочитать состояние окна: {error}"))?;

    if is_maximized {
        let _ = append_interface_event(&app, "Главное окно восстановлено из максимального режима.");
        window
            .unmaximize()
            .map_err(|error| format!("Не удалось восстановить окно: {error}"))
    } else {
        let _ = append_interface_event(&app, "Главное окно развернуто на весь экран.");
        window
            .maximize()
            .map_err(|error| format!("Не удалось развернуть окно: {error}"))
    }
}

#[tauri::command]
fn window_close(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно закрыто.");
    window.close().map_err(|error| format!("Не удалось закрыть окно: {error}"))
}

#[tauri::command]
fn window_hide(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно скрыто в трей.");
    window.hide().map_err(|error| format!("Не удалось скрыть окно: {error}"))
}

#[tauri::command]
fn window_start_drag(window: tauri::WebviewWindow) -> Result<(), String> {
    window
        .start_dragging()
        .map_err(|error| format!("Не удалось начать перемещение окна: {error}"))
}


#[tauri::command]
fn ensure_admin_launch(app: AppHandle) -> Result<bool, String> {
    #[cfg(all(not(debug_assertions), target_os = "windows"))]
    {
        if is_process_elevated()? {
            return Ok(false);
        }

        let executable = std::env::current_exe()
            .map_err(|error| format!("Не удалось определить путь к приложению: {error}"))?;

        let args = std::env::args().skip(1).map(|item| ps_quote(&item)).collect::<Vec<_>>();
        let args_block = if args.is_empty() {
            String::new()
        } else {
            format!(" -ArgumentList @('{}')", args.join("','"))
        };

        let script = format!(
            "Start-Process -FilePath '{}'{} -Verb RunAs",
            ps_quote(&executable.to_string_lossy()),
            args_block
        );

        run_powershell(&script)?;
        cleanup_application(&app, "admin_relaunch");
        app.exit(0);
        Ok(true)
    }

    #[cfg(not(all(not(debug_assertions), target_os = "windows")))]
    {
        let _ = app;
        Ok(false)
    }
}

#[tauri::command]
fn set_launch_on_startup(enabled: bool, app: AppHandle) -> Result<bool, String> {
    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    {
        let executable = std::env::current_exe()
            .map_err(|error| format!("Не удалось определить путь к приложению: {error}"))?;
        let executable = ps_quote(&executable.to_string_lossy());

        let script = if enabled {
            format!(
                r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $key -Force | Out-Null
$exe = '{}'
$quoted = '"' + $exe + '"'
Set-ItemProperty -Path $key -Name '{}' -Value $quoted
"#,
                executable,
                STARTUP_REGISTRY_VALUE
            )
        } else {
            format!(
                r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $key -Name '{}' -ErrorAction SilentlyContinue
"#,
                STARTUP_REGISTRY_VALUE
            )
        };

        run_powershell(&script)?;
        let _ = append_interface_event(
            &app,
            if enabled {
                "Автозапуск приложения включён для текущего пользователя."
            } else {
                "Автозапуск приложения отключён для текущего пользователя."
            },
        );
        Ok(enabled)
    }

    #[cfg(any(not(target_os = "windows"), debug_assertions))]
    {
        let _ = (enabled, app);
        Ok(false)
    }
}

#[tauri::command]
fn proxy_status() -> Result<ProxyStatus, String> {
    current_proxy_snapshot()
}

#[tauri::command]
fn set_system_proxy(enabled: bool, app: AppHandle, state: tauri::State<AppState>) -> Result<ProxyStatus, String> {
    let is_connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    if enabled && !is_connected {
        return Err("Сначала запустите runtime, затем включайте системный proxy.".into());
    }

    let status = if enabled {
        if let Ok(mut previous_guard) = state.previous_proxy.lock() {
            if previous_guard.is_none() {
                *previous_guard = current_proxy_snapshot().ok();
            }
        }
        set_windows_proxy(true)?
    } else {
        let previous = state.previous_proxy.lock().ok().and_then(|mut value| value.take());
        if let Some(snapshot) = previous {
            apply_windows_proxy_snapshot(&snapshot)?
        } else {
            set_windows_proxy(false)?
        }
    };

    let _ = append_runtime_event(
        &app,
        &format!(
            "Windows system proxy {} | server={} | bypass={}",
            if enabled { "включён" } else { "восстановлен/отключён" },
            status.server.clone().unwrap_or_else(|| "—".into()),
            status.bypass.clone().unwrap_or_else(|| "—".into())
        ),
    );
    refresh_tray_menu(&app);
    Ok(status)
}


#[tauri::command]
fn connectivity_probe() -> Result<ConnectivityProbe, String> {
    let checked_at = unix_now_string();
    let http_port_open = tcp_port_open("127.0.0.1", HTTP_PORT, 1200);
    let socks_port_open = tcp_port_open("127.0.0.1", SOCKS_PORT, 1200);

    if !http_port_open {
        return Ok(ConnectivityProbe {
            success: false,
            checked_at,
            http_port_open,
            socks_port_open,
            public_ip: None,
            latency_ms: None,
            message: format!("HTTP inbound 127.0.0.1:{HTTP_PORT} не отвечает. Сначала запустите runtime."),
        });
    }

    let client = build_http_client(Some(&format!("http://127.0.0.1:{HTTP_PORT}")), Duration::from_secs(8))?;

    let started = Instant::now();
    let public_ip = fetch_public_ip(&client)?;

    Ok(ConnectivityProbe {
        success: true,
        checked_at,
        http_port_open,
        socks_port_open,
        public_ip: Some(public_ip),
        latency_ms: Some(started.elapsed().as_millis()),
        message: "Маршрут через локальный Xray runtime отвечает.".into(),
    })
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-Process | Where-Object { $_.Path -and $_.Path.ToLower().EndsWith('.exe') } |
  Sort-Object ProcessName, Id |
  Select-Object -First 80 @{Name='pid';Expression={$_.Id}}, @{Name='name';Expression={ if ($_.ProcessName.ToLower().EndsWith('.exe')) { $_.ProcessName } else { $_.ProcessName + '.exe' } }}, @{Name='path';Expression={$_.Path}}, @{Name='title';Expression={$_.MainWindowTitle}} |
  ConvertTo-Json -Compress
"#;

    let raw = run_powershell(script)?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let value: Value = serde_json::from_str(&raw).map_err(|error| format!("Не удалось прочитать список процессов: {error}"))?;
    let apps: Vec<RunningAppInfo> = if value.is_array() {
        serde_json::from_value(value).map_err(|error| format!("Некорректный список процессов: {error}"))?
    } else {
        vec![serde_json::from_value(value).map_err(|error| format!("Некорректный процесс: {error}"))?]
    };

    Ok(apps
        .into_iter()
        .filter(|app| !app.name.trim().is_empty())
        .collect())
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    Ok(Vec::new())
}

#[tauri::command]
fn restart_application(app: AppHandle) -> Result<(), String> {
    cleanup_application(&app, "restart_application");
    let current_exe = std::env::current_exe().map_err(|error| format!("Не удалось определить путь приложения: {error}"))?;
    let mut command = Command::new(current_exe);
    hide_child_console(&mut command);
    command
        .spawn()
        .map_err(|error| format!("Не удалось перезапустить приложение: {error}"))?;
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn read_runtime_log(app: AppHandle, lines: Option<usize>) -> Result<Vec<String>, String> {
    tail_runtime_log(&app, lines.unwrap_or(20).clamp(1, 200))
}
