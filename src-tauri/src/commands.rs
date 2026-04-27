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

fn client_state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir).map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("client-state-v1.json"))
}

fn is_allowed_client_state_key(key: &str) -> bool {
    matches!(
        key,
        "settings"
            | "splitTunnelEntries"
            | "favoriteServerIds"
            | "selectedServerId"
            | "lastKnownServers"
    )
}

fn read_client_state_map(app: &AppHandle) -> Result<serde_json::Map<String, Value>, String> {
    let path = client_state_path(app)?;
    if !path.exists() {
        return Ok(serde_json::Map::new());
    }

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("Не удалось прочитать сохранённые настройки клиента: {error}"))?;

    if raw.trim().is_empty() {
        return Ok(serde_json::Map::new());
    }

    let value: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Не удалось разобрать сохранённые настройки клиента: {error}"))?;

    Ok(value.as_object().cloned().unwrap_or_default())
}

#[tauri::command]
fn save_client_state_value(key: String, value: String, app: AppHandle) -> Result<(), String> {
    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    let parsed_value: Value = serde_json::from_str(&value)
        .map_err(|error| format!("Не удалось сохранить настройки клиента: некорректный JSON: {error}"))?;

    let mut map = read_client_state_map(&app).unwrap_or_default();
    map.insert(normalized_key.to_string(), parsed_value);
    map.insert(
        "updatedAt".to_string(),
        Value::String(unix_now_string()),
    );

    let payload = serde_json::to_string_pretty(&Value::Object(map))
        .map_err(|error| format!("Не удалось подготовить настройки клиента к сохранению: {error}"))?;

    fs::write(client_state_path(&app)?, payload)
        .map_err(|error| format!("Не удалось сохранить настройки клиента: {error}"))
}

#[tauri::command]
fn load_client_state_value(key: String, app: AppHandle) -> Result<Option<String>, String> {
    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    let map = read_client_state_map(&app)?;
    Ok(map
        .get(normalized_key)
        .and_then(|value| serde_json::to_string(value).ok()))
}

#[tauri::command]
fn clear_client_state_value(key: String, app: AppHandle) -> Result<(), String> {
    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    let mut map = read_client_state_map(&app).unwrap_or_default();
    map.remove(normalized_key);
    map.insert("updatedAt".to_string(), Value::String(unix_now_string()));

    let payload = serde_json::to_string_pretty(&Value::Object(map))
        .map_err(|error| format!("Не удалось подготовить настройки клиента к сохранению: {error}"))?;

    fs::write(client_state_path(&app)?, payload)
        .map_err(|error| format!("Не удалось сохранить настройки клиента: {error}"))
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
    let _operation_guard = state
        .operation_lock
        .try_lock()
        .map_err(|_| "Runtime уже выполняет другое действие. Повторите через несколько секунд.".to_string())?;


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
            let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref());
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

    drop(_operation_guard);
    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
fn request_disconnect(state: tauri::State<AppState>, app: AppHandle) -> Result<RuntimeStatus, String> {
    let _operation_guard = state
        .operation_lock
        .try_lock()
        .map_err(|_| "Runtime уже выполняет другое действие. Повторите через несколько секунд.".to_string())?;

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
    drop(_operation_guard);
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
        let executable = format!("\"{}\"", executable.to_string_lossy());
        let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

        if enabled {
            let mut command = Command::new("reg");
            command.args(["add", run_key, "/v", STARTUP_REGISTRY_VALUE, "/t", "REG_SZ", "/d", &executable, "/f"]);
            run_command_with_timeout(command, Duration::from_secs(4), "enable startup")?;
        } else {
            let mut command = Command::new("reg");
            command.args(["delete", run_key, "/v", STARTUP_REGISTRY_VALUE, "/f"]);
            let _ = run_command_with_timeout(command, Duration::from_secs(4), "disable startup");
        }

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
    let _operation_guard = state
        .operation_lock
        .try_lock()
        .map_err(|_| "Runtime уже выполняет другое действие. Повторите через несколько секунд.".to_string())?;

    let is_connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    if enabled && !is_connected {
        return Err("Сначала запустите runtime, затем включайте системный proxy.".into());
    }

    let status = if enabled {
        capture_previous_proxy_state(&app, &state)?;
        set_windows_proxy(true)?
    } else {
        restore_saved_proxy_state(&app, &state, "manual_proxy_toggle")?
            .unwrap_or_else(|| current_proxy_snapshot().unwrap_or_else(|_| ProxyStatus {
                enabled: false,
                server: None,
                bypass: None,
                method: "unknown".into(),
                scope: "current-user".into(),
                checked_at: unix_now_string(),
            }))
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
            packet_loss_pct: Some(100),
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
        packet_loss_pct: Some(0),
        message: "Маршрут через локальный Xray runtime отвечает.".into(),
    })
}



fn collect_digits_after_marker(raw: &str, marker: &str) -> Vec<u128> {
    let mut values = Vec::new();
    let lower = raw.to_lowercase();
    let mut offset = 0usize;

    while let Some(found) = lower[offset..].find(marker) {
        let start = offset + found + marker.len();
        let tail = &lower[start..];
        let digits = tail
            .chars()
            .skip_while(|ch| ch.is_whitespace())
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();

        if let Ok(value) = digits.parse::<u128>() {
            values.push(value.max(1));
        }

        offset = start.saturating_add(1);
        if offset >= lower.len() {
            break;
        }
    }

    values
}

fn parse_ping_loss_percent(raw: &str) -> Option<u8> {
    let lower = raw.to_lowercase();
    for marker in ["loss", "потер"] {
        if let Some(marker_index) = lower.find(marker) {
            let prefix = &lower[..marker_index];
            if let Some(percent_index) = prefix.rfind('%') {
                let before_percent = &prefix[..percent_index];
                let digits = before_percent
                    .chars()
                    .rev()
                    .skip_while(|ch| ch.is_whitespace())
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();

                if let Ok(value) = digits.parse::<u8>() {
                    return Some(value.min(100));
                }
            }
        }
    }

    None
}

fn parse_ping_output(raw: &str) -> Option<(u128, u8)> {
    let mut samples = Vec::new();
    for marker in ["time=", "time<", "время=", "время<"] {
        samples.extend(collect_digits_after_marker(raw, marker));
    }

    let average_candidates = [
        collect_digits_after_marker(raw, "average ="),
        collect_digits_after_marker(raw, "average="),
        collect_digits_after_marker(raw, "avg ="),
        collect_digits_after_marker(raw, "avg="),
        collect_digits_after_marker(raw, "среднее ="),
        collect_digits_after_marker(raw, "среднее="),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    let latency_ms = average_candidates
        .first()
        .copied()
        .or_else(|| {
            if samples.is_empty() {
                None
            } else {
                Some(samples.iter().sum::<u128>() / samples.len() as u128)
            }
        })?;

    let packet_loss = parse_ping_loss_percent(raw).unwrap_or_else(|| if samples.is_empty() { 100 } else { 0 });
    Some((latency_ms.max(1), packet_loss))
}

#[cfg(target_os = "windows")]
fn windows_icmp_ping(host: &str) -> Option<(u128, u8)> {
    let normalized_host = normalize_socket_host(host);
    if normalized_host.is_empty() {
        return None;
    }

    let force_ipv6 = normalized_host.parse::<Ipv6Addr>().is_ok();
    let mut command = Command::new("ping");
    if force_ipv6 {
        command.args(["-6", "-n", "3", "-w", "1200", &normalized_host]);
    } else {
        // Большинство пользователей работает без IPv6. Принудительно проверяем IPv4,
        // чтобы ping не зависал на AAAA-записях и не показывал ложные 1 мс.
        command.args(["-4", "-n", "3", "-w", "1200", &normalized_host]);
    }

    let output = run_command_with_timeout(command, Duration::from_secs(6), "icmp ping").unwrap_or_else(|error| error);
    parse_ping_output(&output)
}

#[cfg(not(target_os = "windows"))]
fn windows_icmp_ping(_host: &str) -> Option<(u128, u8)> {
    None
}

fn tcp_connect_latency(addresses: &[std::net::SocketAddr], timeout: Duration) -> Option<u128> {
    let mut best: Option<u128> = None;
    let mut ordered = addresses.to_vec();
    ordered.sort_by_key(|address| if address.is_ipv4() { 0 } else { 1 });

    for address in ordered {
        let started = Instant::now();
        if TcpStream::connect_timeout(&address, timeout).is_ok() {
            let elapsed = started.elapsed().as_millis().max(1);
            best = Some(best.map_or(elapsed, |current| current.min(elapsed)));
        }
    }

    best
}


fn run_tcp_ping_samples(addresses: &[std::net::SocketAddr], attempts: u8, timeout: Duration) -> (u8, Option<u128>, u8) {
    let safe_attempts = attempts.max(1);
    let mut success_count: u8 = 0;
    let mut total_ms: u128 = 0;

    for attempt in 0..safe_attempts {
        if let Some(latency) = tcp_connect_latency(addresses, timeout) {
            success_count += 1;
            total_ms += latency;
        }

        if attempt + 1 < safe_attempts {
            std::thread::sleep(Duration::from_millis(80));
        }
    }

    let packet_loss = (((safe_attempts - success_count) as f32 / safe_attempts as f32) * 100.0).round() as u8;
    let latency_ms = if success_count > 0 {
        Some((total_ms / success_count as u128).max(1))
    } else {
        None
    };

    (success_count, latency_ms, packet_loss)
}

fn server_ping_blocking(host: String, port: u16) -> Result<ConnectivityProbe, String> {
    let checked_at = unix_now_string();
    let normalized_host = normalize_socket_host(&host);
    if normalized_host.is_empty() {
        return Err("У выбранного сервера нет host для проверки пинга.".into());
    }

    let addresses = resolve_socket_addresses(&normalized_host, port)?;
    let endpoint = format_endpoint_for_display(&normalized_host, port);

    // Для VPN-сервера важнее не ICMP, а доступность реального host:port.
    // Поэтому TCP-проверка идёт первой и с короткими timeout, чтобы UI не выглядел зависшим.
    let (success_count, latency_ms, packet_loss) = run_tcp_ping_samples(&addresses, 3, Duration::from_millis(850));
    if success_count > 0 {
        return Ok(ConnectivityProbe {
            success: true,
            checked_at,
            http_port_open: tcp_port_open("127.0.0.1", HTTP_PORT, 200),
            socks_port_open: tcp_port_open("127.0.0.1", SOCKS_PORT, 200),
            public_ip: None,
            latency_ms,
            packet_loss_pct: Some(packet_loss),
            message: format!(
                "TCP ping {endpoint}: {} мс, порт доступен, потери {}%.",
                latency_ms.unwrap_or(0),
                packet_loss
            ),
        });
    }

    // ICMP используем только как диагностику. Если ICMP отвечает, но TCP-порт закрыт,
    // сервер не считаем рабочим для подключения, чтобы не показывать ложный зелёный ping.
    if let Some((icmp_latency_ms, icmp_packet_loss)) = windows_icmp_ping(&normalized_host) {
        return Ok(ConnectivityProbe {
            success: false,
            checked_at,
            http_port_open: tcp_port_open("127.0.0.1", HTTP_PORT, 200),
            socks_port_open: tcp_port_open("127.0.0.1", SOCKS_PORT, 200),
            public_ip: None,
            latency_ms: Some(icmp_latency_ms),
            packet_loss_pct: Some(icmp_packet_loss.max(packet_loss)),
            message: format!(
                "ICMP ping {endpoint}: {icmp_latency_ms} мс, но TCP-порт {port} недоступен."
            ),
        });
    }

    Ok(ConnectivityProbe {
        success: false,
        checked_at,
        http_port_open: tcp_port_open("127.0.0.1", HTTP_PORT, 200),
        socks_port_open: tcp_port_open("127.0.0.1", SOCKS_PORT, 200),
        public_ip: None,
        latency_ms: None,
        packet_loss_pct: Some(100),
        message: format!("Ping {endpoint} не получил ответа по TCP/ICMP, потери 100%."),
    })
}

#[tauri::command]
async fn server_ping(host: String, port: u16) -> Result<ConnectivityProbe, String> {
    tauri::async_runtime::spawn_blocking(move || server_ping_blocking(host, port))
        .await
        .map_err(|error| format!("Проверка пинга была прервана: {error}"))?
}

fn parse_xray_stat_value(raw: &str) -> Option<u64> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("value:") {
            if let Ok(parsed) = value.trim().parse::<u64>() {
                return Some(parsed);
            }
        }
    }

    None
}

fn query_xray_stat(core_path: &str, stat_name: &str) -> Result<u64, String> {
    let mut command = Command::new(core_path);
    command
        .arg("api")
        .arg("statsquery")
        .arg(format!("--server=127.0.0.1:{XRAY_API_PORT}"))
        .arg("-name")
        .arg(stat_name);

    let output = run_command_with_timeout(command, Duration::from_secs(3), "xray api statsquery")?;
    // Xray can omit a stat until the first bytes pass through it. Treat a missing
    // value as zero instead of falling back to "unavailable", otherwise the UI
    // never starts showing proxy traffic on fresh connections.
    Ok(parse_xray_stat_value(&output).unwrap_or(0))
}

fn runtime_xray_stats_snapshot(state: &tauri::State<AppState>) -> Option<TrafficSnapshot> {
    let core_path = state
        .runtime
        .lock()
        .ok()
        .and_then(|runtime| runtime.as_ref().map(|item| item.core_path.clone()))?;

    let uplink = query_xray_stat(&core_path, "outbound>>>proxy>>>traffic>>>uplink").ok()?;
    let downlink = query_xray_stat(&core_path, "outbound>>>proxy>>>traffic>>>downlink").ok()?;

    Some(TrafficSnapshot {
        received_bytes: downlink,
        sent_bytes: uplink,
        checked_at: unix_now_string(),
        source: "xray-stats".into(),
    })
}

#[cfg(target_os = "windows")]
fn windows_tun_traffic_snapshot() -> Option<TrafficSnapshot> {
    let script = format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$stats = Get-NetAdapterStatistics -Name '{}' -ErrorAction SilentlyContinue
if ($stats) {{
  [PSCustomObject]@{{ receivedBytes = [UInt64]$stats.ReceivedBytes; sentBytes = [UInt64]$stats.SentBytes }} | ConvertTo-Json -Compress
}}
"#,
        ps_quote(TUN_INTERFACE_NAME)
    );

    let raw = run_powershell(&script).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let value: Value = serde_json::from_str(raw.trim()).ok()?;
    Some(TrafficSnapshot {
        received_bytes: value.get("receivedBytes").and_then(Value::as_u64).unwrap_or(0),
        sent_bytes: value.get("sentBytes").and_then(Value::as_u64).unwrap_or(0),
        checked_at: unix_now_string(),
        source: "windows-tun-adapter".into(),
    })
}

#[cfg(not(target_os = "windows"))]
fn windows_tun_traffic_snapshot() -> Option<TrafficSnapshot> {
    None
}

#[tauri::command]
fn traffic_snapshot(state: tauri::State<AppState>) -> Result<TrafficSnapshot, String> {
    if let Some(snapshot) = runtime_xray_stats_snapshot(&state) {
        return Ok(snapshot);
    }

    if let Some(snapshot) = windows_tun_traffic_snapshot() {
        return Ok(snapshot);
    }

    Ok(TrafficSnapshot {
        received_bytes: 0,
        sent_bytes: 0,
        checked_at: unix_now_string(),
        source: if cfg!(target_os = "windows") { "unavailable".into() } else { "mock".into() },
    })
}

#[cfg(target_os = "windows")]
fn parse_wmic_process_list(raw: &str) -> Vec<RunningAppInfo> {
    raw.lines()
        .skip(1)
        .filter_map(|line| {
            let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.len() < 4 { return None; }
            let pid = parts.last()?.parse::<u32>().ok()?;
            let name = parts.get(parts.len().saturating_sub(2))?.trim().to_string();
            let path = parts[1..parts.len().saturating_sub(2)].join(",").trim().to_string();
            if name.is_empty() || !name.to_lowercase().ends_with(".exe") { return None; }
            Some(RunningAppInfo { pid, name, path: if path.is_empty() { None } else { Some(path) }, title: None })
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn split_csv_line(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => { current.push('"'); let _ = chars.next(); }
            '"' => quoted = !quoted,
            ',' if !quoted => { values.push(current.trim().to_string()); current.clear(); }
            _ => current.push(ch),
        }
    }
    values.push(current.trim().to_string());
    values
}

#[cfg(target_os = "windows")]
fn parse_tasklist_process_list(raw: &str) -> Vec<RunningAppInfo> {
    raw.lines()
        .filter_map(|line| {
            let parts = split_csv_line(line);
            let name = parts.first()?.trim().to_string();
            let pid = parts.get(1)?.trim().parse::<u32>().ok()?;
            if name.is_empty() || !name.to_lowercase().ends_with(".exe") { return None; }
            Some(RunningAppInfo { pid, name, path: None, title: None })
        })
        .collect()
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    let mut wmic = Command::new("wmic");
    wmic.args(["process", "where", "ExecutablePath is not null", "get", "ProcessId,Name,ExecutablePath", "/FORMAT:CSV"]);
    let raw = run_command_with_timeout(wmic, Duration::from_secs(5), "wmic process list");

    let apps = match raw {
        Ok(value) if value.contains("ExecutablePath") => parse_wmic_process_list(&value),
        _ => {
            let mut tasklist = Command::new("tasklist");
            tasklist.args(["/FO", "CSV", "/NH"]);
            let fallback = run_command_with_timeout(tasklist, Duration::from_secs(4), "tasklist process list")?;
            parse_tasklist_process_list(&fallback)
        }
    };

    Ok(apps.into_iter().filter(|app| !app.name.trim().is_empty()).take(80).collect())
}
#[cfg(not(target_os = "windows"))]
#[tauri::command]
fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    Ok(Vec::new())
}

fn read_xray_version(app: &AppHandle) -> (String, Option<String>) {
    let Some(core_path) = resolve_core_path(app) else {
        return ("Не найден".to_string(), None);
    };

    let core_path_string = core_path.to_string_lossy().to_string();

    if let Err(error) = validate_core_path(&core_path) {
        return (format!("Файл Xray повреждён: {error}"), Some(core_path_string));
    }

    let mut command = Command::new(&core_path);
    command.arg("version");
    hide_child_console(&mut command);

    match command.output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first_line = stdout
                .lines()
                .chain(stderr.lines())
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or("Версия не определена")
                .to_string();
            (first_line, Some(core_path_string))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let message = if stderr.is_empty() { stdout } else { stderr };
            (if message.is_empty() { "Не удалось запустить xray.exe".to_string() } else { message }, Some(core_path_string))
        }
        Err(error) => {
            let friendly = if error.raw_os_error() == Some(193) {
                "Ошибка запуска Xray: файл не запускается как Windows x64-приложение (os error 193). Запустите START_VKarmani.bat — он проверит и восстановит core.".to_string()
            } else {
                format!("Не удалось запустить Xray-core: {error}")
            };
            (friendly, Some(core_path_string))
        },
    }
}
#[cfg(target_os = "windows")]
fn read_windows_registry_value(key: &str, value_name: &str) -> Option<String> {
    let mut command = Command::new("reg");
    command.args(["query", key, "/v", value_name]);
    run_command_with_timeout(command, Duration::from_secs(4), &format!("reg query {value_name}"))
        .ok()
        .and_then(|raw| parse_reg_value(&raw, value_name))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "windows")]
fn windows_device_info() -> (String, String, String, String, String, String) {
    let current_version_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let hwid = read_windows_registry_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        .unwrap_or_else(|| "—".to_string());
    let product_name = read_windows_registry_value(current_version_key, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let display_version = read_windows_registry_value(current_version_key, "DisplayVersion")
        .or_else(|| read_windows_registry_value(current_version_key, "ReleaseId"))
        .unwrap_or_else(|| "—".to_string());
    let build = read_windows_registry_value(current_version_key, "CurrentBuildNumber")
        .or_else(|| read_windows_registry_value(current_version_key, "CurrentBuild"))
        .unwrap_or_else(|| "—".to_string());
    let architecture = std::env::var("PROCESSOR_ARCHITECTURE")
        .or_else(|_| std::env::var("PROCESSOR_ARCHITEW6432"))
        .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    let device_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "—".to_string());

    (hwid, product_name, display_version, build, architecture, device_name)
}
#[cfg(not(target_os = "windows"))]
fn windows_device_info() -> (String, String, String, String, String, String) {
    (
        "—".to_string(),
        std::env::consts::OS.to_string(),
        "—".to_string(),
        "—".to_string(),
        std::env::consts::ARCH.to_string(),
        std::env::var("HOSTNAME").unwrap_or_else(|_| "—".to_string()),
    )
}

#[tauri::command]
fn native_app_info(app: AppHandle) -> NativeAppInfo {
    let (xray_version, core_path) = read_xray_version(&app);
    let (hwid, os_name, os_version, os_build, os_architecture, device_name) = windows_device_info();

    NativeAppInfo {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        xray_version,
        hwid,
        os_name,
        os_version,
        os_build,
        os_architecture,
        device_name,
        core_path,
    }
}

#[cfg(target_os = "windows")]
#[tauri::command]
fn pick_executable_path() -> Result<Option<String>, String> {
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Выберите приложение для TUN'
$dialog.Filter = 'Windows applications (*.exe)|*.exe|All files (*.*)|*.*'
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  $dialog.FileName
}
"#;

    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-STA", "-Command", script]);
    hide_child_console(&mut command);

    let output = command
        .output()
        .map_err(|error| format!("Не удалось открыть выбор приложения: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if stderr.is_empty() { stdout } else { stderr });
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if value.is_empty() { None } else { Some(value) })
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
fn pick_executable_path() -> Result<Option<String>, String> {
    Ok(None)
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
