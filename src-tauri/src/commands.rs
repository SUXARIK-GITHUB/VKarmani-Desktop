use super::*;

#[tauri::command]
pub(crate) fn write_interface_log(message: String, details: Option<String>, app: AppHandle) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_interface_event(&app, &line)
}

#[tauri::command]
pub(crate) fn write_routing_log(message: String, details: Option<String>, app: AppHandle) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_runtime_event(&app, &line)
}

#[tauri::command]
pub(crate) async fn public_ip_snapshot(mode: Option<String>) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || public_ip_snapshot_blocking(mode))
        .await
        .map_err(|error| format!("Проверка внешнего IP была прервана: {error}"))?
}

pub(crate) fn public_ip_snapshot_blocking(mode: Option<String>) -> Result<String, String> {
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

pub(crate) const CLIENT_STATE_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const NATIVE_SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const VKARMANI_ACCESS_KEY_PREFIX: &str = "https://sub.vkarmani.com/";

pub(crate) fn atomic_write_text(path: &Path, payload: &str, context: &str) -> Result<(), String> {
    if payload.len() as u64 > CLIENT_STATE_MAX_BYTES {
        return Err(format!("{context}: файл настроек слишком большой"));
    }

    let parent = path
        .parent()
        .ok_or_else(|| format!("{context}: не удалось определить папку для файла"))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("{context}: не удалось создать папку для файла: {error}"))?;

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("client-state");
    let write_nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        write_nonce
    ));
    let backup_path = parent.join(format!(".{file_name}.bak"));

    {
        let mut file = File::create(&tmp_path)
            .map_err(|error| format!("{context}: не удалось создать временный файл: {error}"))?;
        file.write_all(payload.as_bytes())
            .map_err(|error| format!("{context}: не удалось записать временный файл: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("{context}: не удалось синхронизировать временный файл: {error}"))?;
    }

    let backup_created = if path.exists() {
        fs::copy(path, &backup_path)
            .map_err(|error| format!("{context}: не удалось создать резервную копию перед заменой файла: {error}"))?;
        true
    } else {
        false
    };

    match fs::rename(&tmp_path, path) {
        Ok(()) => {
            if backup_created {
                let _ = fs::remove_file(&backup_path);
            }
            Ok(())
        }
        Err(first_error) => {
            // Windows не умеет rename поверх существующего файла через std::fs.
            // Поэтому держим backup и делаем безопасный fallback remove + rename.
            if path.exists() {
                fs::remove_file(path)
                    .map_err(|error| format!("{context}: не удалось заменить старый файл: {error}; первая ошибка rename: {first_error}"))?;
            }

            match fs::rename(&tmp_path, path) {
                Ok(()) => {
                    if backup_created {
                        let _ = fs::remove_file(&backup_path);
                    }
                    Ok(())
                }
                Err(second_error) => {
                    let _ = fs::remove_file(&tmp_path);
                    if backup_created && backup_path.exists() && !path.exists() {
                        let _ = fs::rename(&backup_path, path);
                    }
                    Err(format!(
                        "{context}: не удалось заменить файл настроек: {second_error}; первая ошибка rename: {first_error}"
                    ))
                }
            }
        }
    }
}

pub(crate) fn normalize_access_key_for_native(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_string();
    if !normalized.to_ascii_lowercase().starts_with(VKARMANI_ACCESS_KEY_PREFIX) {
        return Err("Ключ VKarmani должен начинаться с https://sub.vkarmani.com/.".to_string());
    }
    if normalized.len() < VKARMANI_ACCESS_KEY_PREFIX.len() + 8 {
        return Err("Ключ VKarmani выглядит слишком коротким.".to_string());
    }
    Ok(normalized)
}

pub(crate) fn secure_access_key_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir).map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("access-key.dpapi"))
}

pub(crate) fn client_state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir).map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("client-state-v1.json"))
}

pub(crate) fn is_allowed_client_state_key(key: &str) -> bool {
    matches!(
        key,
        "settings"
            | "splitTunnelEntries"
            | "favoriteServerIds"
            | "selectedServerId"
            | "lastKnownServers"
    )
}

pub(crate) fn read_client_state_map(app: &AppHandle) -> Result<serde_json::Map<String, Value>, String> {
    let path = client_state_path(app)?;
    if !path.exists() {
        return Ok(serde_json::Map::new());
    }

    let metadata = fs::metadata(&path)
        .map_err(|error| format!("Не удалось проверить сохранённые настройки клиента: {error}"))?;
    if metadata.len() > CLIENT_STATE_MAX_BYTES {
        return Err("Файл сохранённых настроек клиента слишком большой и не будет загружен.".to_string());
    }

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("Не удалось прочитать сохранённые настройки клиента: {error}"))?;

    if raw.trim().is_empty() {
        return Ok(serde_json::Map::new());
    }

    let value: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(error) => {
            let backup_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .map(|name| format!("{name}.corrupt-{}", unix_timestamp_seconds()))
                .unwrap_or_else(|| format!("client-state-v1.json.corrupt-{}", unix_timestamp_seconds()));
            let backup_path = path.with_file_name(backup_name);
            let _ = fs::copy(&path, &backup_path);
            let _ = append_interface_event(
                app,
                &format!(
                    "Сохранённые настройки клиента повреждены и не будут загружены: {error}. Backup: {}",
                    backup_path.display()
                ),
            );
            return Ok(serde_json::Map::new());
        }
    };

    Ok(value.as_object().cloned().unwrap_or_default())
}

#[tauri::command]
pub(crate) fn save_client_state_value(key: String, value: String, app: AppHandle) -> Result<(), String> {
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

    let path = client_state_path(&app)?;
    atomic_write_text(&path, &payload, "Не удалось сохранить настройки клиента")
}

#[tauri::command]
pub(crate) fn load_client_state_value(key: String, app: AppHandle) -> Result<Option<String>, String> {
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
pub(crate) fn clear_client_state_value(key: String, app: AppHandle) -> Result<(), String> {
    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    let mut map = read_client_state_map(&app).unwrap_or_default();
    map.remove(normalized_key);
    map.insert("updatedAt".to_string(), Value::String(unix_now_string()));

    let payload = serde_json::to_string_pretty(&Value::Object(map))
        .map_err(|error| format!("Не удалось подготовить настройки клиента к сохранению: {error}"))?;

    let path = client_state_path(&app)?;
    atomic_write_text(&path, &payload, "Не удалось сохранить настройки клиента")
}


#[cfg(target_os = "windows")]
pub(crate) fn encrypt_access_key(value: &str) -> Result<String, String> {
    let mut input = DataBlob {
        cb_data: value.as_bytes().len() as u32,
        pb_data: value.as_bytes().as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &mut input,
            null(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if ok == 0 {
        return Err(format!("DPAPI CryptProtectData не смог зашифровать ключ: {}", std::io::Error::last_os_error()));
    }

    let encrypted = unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe {
        LocalFree(output.pb_data as *mut core::ffi::c_void);
    }

    Ok(general_purpose::STANDARD.encode(encrypted))
}

#[cfg(target_os = "windows")]
pub(crate) fn decrypt_access_key(value: &str) -> Result<String, String> {
    let encrypted = general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|error| format!("DPAPI blob повреждён или не является base64: {error}"))?;

    let mut input = DataBlob {
        cb_data: encrypted.len() as u32,
        pb_data: encrypted.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if ok == 0 {
        return Err(format!("DPAPI CryptUnprotectData не смог расшифровать ключ: {}", std::io::Error::last_os_error()));
    }

    let decrypted = unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe {
        LocalFree(output.pb_data as *mut core::ffi::c_void);
    }

    String::from_utf8(decrypted)
        .map_err(|error| format!("DPAPI вернул не UTF-8 ключ доступа: {error}"))
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn encrypt_access_key(value: &str) -> Result<String, String> {
    Ok(value.to_string())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn decrypt_access_key(value: &str) -> Result<String, String> {
    Ok(value.to_string())
}

#[tauri::command]
pub(crate) fn save_access_key_secure(value: String, app: AppHandle) -> Result<(), String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return clear_access_key_secure(app);
    }
    let normalized = normalize_access_key_for_native(normalized)?;
    let encrypted = encrypt_access_key(&normalized)?;
    let path = secure_access_key_path(&app)?;
    atomic_write_text(&path, &encrypted, "Не удалось сохранить ключ доступа в защищённое хранилище")
}

#[tauri::command]
pub(crate) fn load_access_key_secure(app: AppHandle) -> Result<Option<String>, String> {
    let path = secure_access_key_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("Не удалось проверить защищённый ключ доступа: {error}"))?;
    if metadata.len() > 64 * 1024 {
        return Err("Файл защищённого ключа выглядит слишком большим и не будет загружен.".to_string());
    }

    let encrypted = fs::read_to_string(path)
        .map_err(|error| format!("Не удалось прочитать защищённый ключ доступа: {error}"))?;
    let value = decrypt_access_key(encrypted.trim())?;
    Ok(Some(normalize_access_key_for_native(&value)?))
}

#[tauri::command]
pub(crate) fn clear_access_key_secure(app: AppHandle) -> Result<(), String> {
    let path = secure_access_key_path(&app)?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| format!("Не удалось удалить сохранённый ключ доступа: {error}"))?;
    }
    Ok(())
}



#[tauri::command]
pub(crate) fn bootstrap_info() -> BootstrapInfo {
    BootstrapInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
    }
}


pub(crate) fn clear_native_session_authorization(state: &tauri::State<AppState>) -> Result<(), String> {
    *state
        .session_authorized
        .lock()
        .map_err(|_| "Не удалось обновить состояние авторизации.".to_string())? = false;
    *state
        .session_authorization
        .lock()
        .map_err(|_| "Не удалось очистить native-сессию.".to_string())? = None;
    Ok(())
}

pub(crate) fn ensure_native_session_authorized(app: &AppHandle, state: &tauri::State<AppState>) -> Result<(), String> {
    let is_authorized = *state
        .session_authorized
        .lock()
        .map_err(|_| "Не удалось проверить состояние авторизации.".to_string())?;
    if !is_authorized {
        return Err("Сначала войдите по ключу VKarmani, затем запускайте подключение.".into());
    }

    let auth = state
        .session_authorization
        .lock()
        .map_err(|_| "Не удалось проверить native-сессию.".to_string())?
        .clone()
        .ok_or_else(|| "Native-сессия не подтверждена. Войдите по ключу ещё раз.".to_string())?;

    let now = unix_timestamp_seconds();
    if auth.expires_at <= now {
        drop(auth);
        clear_native_session_authorization(state)?;
        refresh_tray_menu(app);
        return Err("Native-сессия устарела. Войдите по ключу VKarmani ещё раз.".into());
    }

    if auth.access_key_hash.len() != 64 || !auth.access_key_hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("Native-сессия повреждена. Войдите по ключу VKarmani ещё раз.".into());
    }

    Ok(())
}

#[tauri::command]
pub(crate) fn set_tray_update_state(
    available: bool,
    busy: bool,
    state: tauri::State<AppState>,
    app: AppHandle,
) -> Result<bool, String> {
    *state
        .tray_update_available
        .lock()
        .map_err(|_| "Не удалось обновить состояние обновлений в трее.".to_string())? = available;
    *state
        .tray_update_busy
        .lock()
        .map_err(|_| "Не удалось обновить статус проверки обновлений в трее.".to_string())? = busy;

    let _ = append_interface_event(
        &app,
        if busy {
            "Tray updater: действие обновления выполняется, пункт меню временно заблокирован."
        } else if available {
            "Tray updater: найдено обновление, пункт меню изменён на установку."
        } else {
            "Tray updater: обновлений нет, пункт меню изменён на проверку."
        },
    );
    refresh_tray_menu(&app);
    Ok(true)
}

#[tauri::command]
pub(crate) fn set_session_authorized(
    authorized: bool,
    access_key: Option<String>,
    state: tauri::State<AppState>,
    app: AppHandle,
) -> Result<bool, String> {
    if authorized {
        let normalized_access_key = normalize_access_key_for_native(
            access_key
                .as_deref()
                .ok_or_else(|| "Для подтверждения native-сессии нужен ключ доступа.".to_string())?,
        )?;
        let now = unix_timestamp_seconds();
        let auth = NativeSessionAuthorization {
            access_key_hash: sha256_hex_bytes(normalized_access_key.as_bytes()),
            expires_at: now.saturating_add(NATIVE_SESSION_TTL_SECONDS),
        };

        *state
            .session_authorized
            .lock()
            .map_err(|_| "Не удалось обновить состояние авторизации.".to_string())? = true;
        *state
            .session_authorization
            .lock()
            .map_err(|_| "Не удалось сохранить native-сессию.".to_string())? = Some(auth);
    } else {
        clear_native_session_authorization(&state)?;
    }

    let _ = append_interface_event(
        &app,
        if authorized {
            "Сессия ЛК активна: native-сессия подтверждена и меню трея обновлено."
        } else {
            "Сессия ЛК завершена: native-сессия очищена и меню трея обновлено."
        },
    );
    refresh_tray_menu(&app);
    Ok(authorized)
}

#[tauri::command]
pub(crate) async fn runtime_status(app: AppHandle) -> RuntimeStatus {
    let app_for_task = app.clone();
    match tauri::async_runtime::spawn_blocking(move || {
        let state = app_for_task.state::<AppState>();
        build_runtime_status(&app_for_task, state)
    })
    .await
    {
        Ok(status) => status,
        Err(_) => {
            let state = app.state::<AppState>();
            build_runtime_status(&app, state)
        }
    }
}

pub(crate) fn wait_for_xray_runtime_ready(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    child: &mut Child,
    log_path: &Path,
    core_working_dir: &Path,
    network_mode: &str,
) -> Result<(), String> {
    let timeout = if network_mode == "tun" {
        Duration::from_millis(15_000)
    } else {
        Duration::from_millis(10_000)
    };
    let started_at = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Не удалось проверить статус Xray-core: {error}"))?
        {
            let code = status.code();
            if let Ok(mut exit_guard) = state.last_exit_code.lock() {
                *exit_guard = code;
            }
            let log_excerpt = read_runtime_log_excerpt(log_path, 8);
            let joined_excerpt = log_excerpt.join(" | ");
            let _ = append_runtime_event(
                app,
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

        let http_ready = tcp_port_open("127.0.0.1", HTTP_PORT, 80);
        let socks_ready = tcp_port_open("127.0.0.1", SOCKS_PORT, 80);
        let api_ready = tcp_port_open("127.0.0.1", XRAY_API_PORT, 80);
        let ports_state = format!("http={http_ready} socks={socks_ready} api={api_ready}");

        if http_ready && socks_ready && api_ready {
            let _ = append_runtime_event(app, &format!("Xray локальные порты готовы: {ports_state}."));
            return Ok(());
        }

        if started_at.elapsed() >= timeout {
            let log_excerpt = read_runtime_log_excerpt(log_path, 8).join(" | ");
            let details = if log_excerpt.is_empty() {
                "Лог Xray пока пуст.".to_string()
            } else {
                format!("Последние строки xray-runtime.log: {log_excerpt}")
            };
            return Err(format!(
                "Xray запущен, но локальные порты не стали готовы за {} мс ({ports_state}). {details}",
                timeout.as_millis()
            ));
        }

        std::thread::sleep(Duration::from_millis(90));
    }
}

#[tauri::command]
pub(crate) async fn request_connect(
    server_id: String,
    server_label: String,
    server_fingerprint: Option<String>,
    runtime_template: RuntimeTemplate,
    network_mode: Option<String>,
    ip_stack: Option<String>,
    reconnect: Option<bool>,
    split_tunnel_entries: Option<Vec<SplitTunnelEntryPayload>>,
    routing_exclusions: Option<RoutingExclusionSettingsPayload>,
    app: AppHandle,
) -> Result<RuntimeStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        request_connect_blocking(
            server_id,
            server_label,
            server_fingerprint,
            runtime_template,
            network_mode,
            ip_stack,
            reconnect,
            split_tunnel_entries,
            routing_exclusions,
            app,
        )
    })
    .await
    .map_err(|error| format!("Подключение Xray было прервано: {error}"))?
}

pub(crate) fn validate_xray_config_with_core(core_path: &Path, config_path: &Path) -> Result<(), String> {
    let core_working_dir = core_path.parent().ok_or_else(|| {
        "Не удалось определить рабочую папку Xray-core для проверки config.".to_string()
    })?;

    let mut command = Command::new(core_path);
    command
        .current_dir(core_working_dir)
        .env("XRAY_LOCATION_ASSET", core_working_dir)
        .env("XRAY_LOCATION_CONFIG", config_path.parent().unwrap_or(core_working_dir))
        .arg("run")
        .arg("-test")
        .arg("-config")
        .arg(config_path)
        .stdin(Stdio::null());

    run_command_with_timeout(command, Duration::from_secs(8), "xray config test")
        .map(|_| ())
        .map_err(|error| format!("Xray-core не принял runtime-конфиг. Подключение остановлено до запуска процесса: {error}"))
}

pub(crate) fn request_connect_blocking(
    server_id: String,
    server_label: String,
    server_fingerprint: Option<String>,
    runtime_template: RuntimeTemplate,
    network_mode: Option<String>,
    ip_stack: Option<String>,
    reconnect: Option<bool>,
    split_tunnel_entries: Option<Vec<SplitTunnelEntryPayload>>,
    routing_exclusions: Option<RoutingExclusionSettingsPayload>,
    app: AppHandle,
) -> Result<RuntimeStatus, String> {
    let state = app.state::<AppState>();
    ensure_native_session_authorized(&app, &state)?;

    if runtime_template.family.to_lowercase() != "xray" {
        return Err("Сейчас поддерживается только Xray runtime family.".into());
    }
    let _operation_guard = acquire_operation_lock(&state, Duration::from_secs(8), "connect")?;


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

    let normalized_ip_stack = match ip_stack
        .unwrap_or_else(|| "ipv4".to_string())
        .trim()
        .to_lowercase()
        .as_str()
    {
        "ipv6" | "6" => "ipv6".to_string(),
        _ => "ipv4".to_string(),
    };

    if normalized_network_mode == "tun" && normalized_ip_stack == "ipv6" {
        return Err("IPv6 режим сейчас доступен только для Proxy. TUN оставлен IPv4-only, чтобы не получить IPv6 loop/leak при переключении маршрутов Windows. Выберите IPv4 или используйте Proxy режим.".into());
    }

    let reconnect_requested = reconnect.unwrap_or(false);

    let active_split_tunnel_entries = split_tunnel_entries
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry.enabled && !entry.value.trim().is_empty())
        .collect::<Vec<_>>();

    if normalized_network_mode == "tun" && active_split_tunnel_entries.is_empty() {
        return Err("Для TUN режима нужно добавить хотя бы одну включённую программу или службу. Пустой TUN не запускается, чтобы случайно не пустить весь трафик мимо VPN.".into());
    }

    let (outbound_host, outbound_port) = extract_outbound_address_and_port(&runtime_template);

    if normalized_network_mode == "tun" && outbound_host.as_deref().map(|value| value.trim()).unwrap_or_default().is_empty() {
        return Err("TUN режим не может стартовать: в runtime-конфиге не удалось определить адрес VPN-сервера. Выберите другой сервер или используйте Proxy режим.".into());
    }

    #[cfg(target_os = "windows")]
    if normalized_network_mode == "tun" && !is_process_elevated()? {
        return Err("TUN режим требует запуска VKarmani с правами администратора, иначе Windows не даст создать маршруты. Откройте настройки клиента и включите запуск от администратора или перезапустите приложение вручную от имени администратора.".into());
    }

    stop_existing_runtime(&app, &state, !reconnect_requested)?;
    stop_orphan_xray_processes(&app, &core_path);
    if let Err(first_release_error) = wait_for_runtime_ports_release(if reconnect_requested { Duration::from_secs(6) } else { Duration::from_secs(4) }) {
        let _ = append_runtime_event(
            &app,
            &format!("Локальные порты не освободились с первой попытки, выполняю повторную очистку Xray перед стартом нового сервера: {first_release_error}"),
        );
        stop_orphan_xray_processes(&app, &core_path);
        wait_for_runtime_ports_release(Duration::from_secs(4)).map_err(|second_release_error| {
            format!("{first_release_error}; повторная очистка Xray не освободила порты: {second_release_error}")
        })?;
    }
    if reconnect_requested {
        let _ = append_runtime_event(&app, "Старый Xray остановлен, локальные порты освобождены, запускаем выбранный сервер без наложения процессов.");
    }
    ensure_runtime_ports_available()?;

    // Важно: определяем outbound_ip/sendThrough только после остановки старого runtime.
    // Иначе при переключении из активного TUN Windows могла вернуть TUN/виртуальный
    // адрес как основной, новый Xray стартовал с неправильным sendThrough и мог
    // загнать собственный outbound в петлю с высоким CPU.
    let outbound_ip = outbound_host
        .as_deref()
        .and_then(|host| resolve_ipv4_address(host, outbound_port));
    let send_through_ip = if normalized_network_mode == "tun" {
        detect_primary_ipv4_address()
    } else {
        None
    };

    if normalized_network_mode == "tun" && outbound_ip.is_none() {
        return Err(format!(
            "TUN режим пока поддерживает только серверы с IPv4 endpoint. Для сервера {} не удалось получить IPv4 адрес. Выберите другой сервер или используйте Proxy режим.",
            outbound_host.as_deref().unwrap_or("—")
        ));
    }

    if normalized_network_mode == "tun" && send_through_ip.is_none() {
        return Err("Не удалось определить локальный IPv4 адрес активного сетевого адаптера для TUN режима. Подключитесь к сети без VPN/виртуального адаптера и попробуйте снова.".into());
    }

    let output_dir = runtime_output_dir(&app)?;
    let _ = cleanup_runtime_config_files(&app);
    let config_path = output_dir.join(format!("xray-config-{}-{}.json", std::process::id(), unix_now_string()));
    let runtime_trace_path = runtime_log_path(&app)?;
    let _ = fs::write(&runtime_trace_path, "");
    let log_path = runtime_trace_path.clone();

    let (config, split_tunnel_plan, routing_exclusion_plan) = build_xray_config(
        &runtime_template,
        &normalized_network_mode,
        &normalized_ip_stack,
        send_through_ip.as_deref(),
        &active_split_tunnel_entries,
        routing_exclusions.as_ref(),
        Some(runtime_trace_path.as_path()),
    );

    if normalized_network_mode == "tun" && split_tunnel_plan.process_matches.is_empty() {
        for note in &split_tunnel_plan.skipped_notes {
            let _ = append_runtime_event(&app, note);
        }
        return Err("TUN режим не запущен: выбранные программы/службы не удалось превратить в безопасные правила процессов. Добавьте обычный .exe файл приложения или выберите Proxy режим.".into());
    }

    let config_text = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Не удалось сериализовать config: {error}"))?;
    fs::write(&config_path, config_text).map_err(|error| format!("Не удалось записать config: {error}"))?;

    validate_xray_config_with_core(&core_path, &config_path).map_err(|error| {
        let _ = append_runtime_event(&app, &error);
        error
    })?;

    if normalized_network_mode == "tun" {
        let core_dir = core_path.parent().map(|value| value.to_path_buf());
        let geoip_status = core_dir
            .as_ref()
            .map(|dir| {
                let path = dir.join("geoip.dat");
                if !path.exists() {
                    "нет файла".to_string()
                } else {
                    verify_core_manifest_artifact(&path, "geoip.dat").map(|_| "ok".to_string()).unwrap_or_else(|error| error)
                }
            })
            .unwrap_or_else(|| "не удалось определить папку core".to_string());
        let geosite_status = core_dir
            .as_ref()
            .map(|dir| {
                let path = dir.join("geosite.dat");
                if !path.exists() {
                    "нет файла".to_string()
                } else {
                    verify_core_manifest_artifact(&path, "geosite.dat").map(|_| "ok".to_string()).unwrap_or_else(|error| error)
                }
            })
            .unwrap_or_else(|| "не удалось определить папку core".to_string());
        let wintun_status = core_dir
            .as_ref()
            .map(|dir| {
                let path = dir.join("wintun.dll");
                if !path.exists() {
                    "нет файла".to_string()
                } else {
                    validate_core_sidecar_path(&path, "wintun.dll").map(|_| "ok".to_string()).unwrap_or_else(|error| error)
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
                geoip_status,
                geosite_status,
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
            "Запуск Xray runtime для {server_label} · mode={} · protocol={} · reconnect={} · remarks={}",
            normalized_network_mode,
            runtime_template.protocol,
            reconnect_requested,
            runtime_template.remarks.unwrap_or_else(|| "—".into())
        ),
    )?;

    if normalized_network_mode == "tun" {
        let _ = append_runtime_event(
            &app,
            &format!(
                "TUN selective mode: {} app rule(s), {} service rule(s), total process matches {}.",
                split_tunnel_plan.resolved_apps,
                split_tunnel_plan.resolved_services,
                split_tunnel_plan.process_matches.len()
            ),
        );

        for note in &split_tunnel_plan.skipped_notes {
            let _ = append_runtime_event(&app, note);
        }
    }

    if !routing_exclusion_plan.domain_rules.is_empty() || !routing_exclusion_plan.ip_rules.is_empty() {
        let _ = append_runtime_event(
            &app,
            &format!(
                "Routing exclusions active: {} domain rule(s), {} IPv4/CIDR rule(s) routed direct outside VPN.",
                routing_exclusion_plan.domain_rules.len(),
                routing_exclusion_plan.ip_rules.len()
            ),
        );
    }

    for note in &routing_exclusion_plan.skipped_notes {
        let _ = append_runtime_event(&app, note);
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
        .env("XRAY_LOCATION_ASSET", core_working_dir)
        .env("XRAY_LOCATION_CONFIG", &output_dir)
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

    if let Err(error) = wait_for_xray_runtime_ready(
        &app,
        &state,
        &mut child,
        &log_path,
        core_working_dir,
        &normalized_network_mode,
    ) {
        let _ = append_runtime_event(
            &app,
            &format!("Xray runtime не стал готовым после запуска, выполняю аварийную очистку: {error}"),
        );
        let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref());
        let _ = restore_saved_proxy_state(&app, &state, "connect_readiness_failed");
        let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
        return Err(error);
    }

    if normalized_network_mode == "tun" {
        configure_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref()).map_err(|error| {
            let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref());
            let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
            format!("Не удалось подготовить Windows-маршруты для TUN режима: {error}")
        })?;
        if let Err(error) = apply_tun_ipv6_route_guard(TUN_INTERFACE_NAME) {
            let _ = append_runtime_event(
                &app,
                &format!("TUN IPv6 leak guard не применился, подключение остановлено для защиты от утечек IPv6: {error}"),
            );
            let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref());
            let _ = restore_saved_proxy_state(&app, &state, "tun_ipv6_guard_failed");
            let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
            return Err(format!(
                "Не удалось включить защиту TUN от IPv6-утечек: {error}. Подключение остановлено, чтобы не пропускать IPv6 мимо VPN."
            ));
        }
        let _ = append_runtime_event(&app, "TUN IPv6 leak guard применён: IPv6 split-default направлен в TUN, Xray дополнительно блокирует IPv6 на tun-in.");
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
            server_fingerprint: server_fingerprint.clone().filter(|value| !value.trim().is_empty()),
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
pub(crate) async fn request_disconnect(app: AppHandle) -> Result<RuntimeStatus, String> {
    tauri::async_runtime::spawn_blocking(move || request_disconnect_blocking(app))
        .await
        .map_err(|error| format!("Отключение Xray было прервано: {error}"))?
}

pub(crate) fn request_disconnect_blocking(app: AppHandle) -> Result<RuntimeStatus, String> {
    let state = app.state::<AppState>();
    let _operation_guard = acquire_operation_lock(&state, Duration::from_secs(8), "runtime-operation")?;

    stop_existing_runtime(&app, &state, true)?;

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
pub(crate) fn cache_profile_sync(profile_count: usize, source: String, state: tauri::State<AppState>, app: AppHandle) {
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
pub(crate) fn request_show(app: AppHandle) {
    let _ = append_interface_event(&app, "Окно приложения раскрыто пользователем.");
    reveal_main_window(&app);
}

#[tauri::command]
pub(crate) fn window_minimize(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно свёрнуто.");
    window.minimize().map_err(|error| format!("Не удалось свернуть окно: {error}"))
}

#[tauri::command]
pub(crate) fn window_toggle_maximize(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
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
pub(crate) fn window_close(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно закрыто.");
    window.close().map_err(|error| format!("Не удалось закрыть окно: {error}"))
}

#[tauri::command]
pub(crate) fn window_hide(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно скрыто в трей.");
    window.hide().map_err(|error| format!("Не удалось скрыть окно: {error}"))
}

#[tauri::command]
pub(crate) fn ensure_admin_launch(app: AppHandle) -> Result<bool, String> {
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
pub(crate) fn set_launch_on_startup(enabled: bool, app: AppHandle) -> Result<bool, String> {
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
pub(crate) async fn proxy_status() -> Result<ProxyStatus, String> {
    tauri::async_runtime::spawn_blocking(current_proxy_snapshot)
        .await
        .map_err(|error| format!("Проверка Windows proxy была прервана: {error}"))?
}

#[tauri::command]
pub(crate) async fn set_system_proxy(enabled: bool, app: AppHandle) -> Result<ProxyStatus, String> {
    tauri::async_runtime::spawn_blocking(move || set_system_proxy_blocking(enabled, app))
        .await
        .map_err(|error| format!("Изменение Windows proxy было прервано: {error}"))?
}

pub(crate) fn set_system_proxy_blocking(enabled: bool, app: AppHandle) -> Result<ProxyStatus, String> {
    let state = app.state::<AppState>();
    let _operation_guard = acquire_operation_lock(&state, Duration::from_secs(6), "runtime-operation")?;

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
pub(crate) async fn repair_runtime_environment(app: AppHandle) -> Result<RuntimeStatus, String> {
    tauri::async_runtime::spawn_blocking(move || repair_runtime_environment_blocking(app))
        .await
        .map_err(|error| format!("Восстановление runtime окружения было прервано: {error}"))?
}

pub(crate) fn repair_runtime_environment_blocking(app: AppHandle) -> Result<RuntimeStatus, String> {
    let state = app.state::<AppState>();
    let _operation_guard = acquire_operation_lock(&state, Duration::from_secs(6), "runtime-operation")?;

    let is_connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    if is_connected {
        return Err("Сначала отключите VPN, затем запускайте восстановление runtime окружения.".into());
    }

    let _ = restore_saved_proxy_state(&app, &state, "manual_runtime_repair");
    let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, None);
    let _ = cleanup_runtime_config_files(&app);
    let _ = append_runtime_event(&app, "Выполнено ручное восстановление runtime окружения: proxy/routes/runtime-config cleanup.");
    refresh_tray_menu(&app);
    drop(_operation_guard);
    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
pub(crate) async fn connectivity_probe() -> Result<ConnectivityProbe, String> {
    tauri::async_runtime::spawn_blocking(connectivity_probe_blocking)
        .await
        .map_err(|error| format!("Проверка маршрута была прервана: {error}"))?
}

pub(crate) fn connectivity_probe_blocking() -> Result<ConnectivityProbe, String> {
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



pub(crate) fn collect_digits_after_marker(raw: &str, marker: &str) -> Vec<u128> {
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

pub(crate) fn parse_ping_loss_percent(raw: &str) -> Option<u8> {
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

pub(crate) fn parse_ping_output(raw: &str) -> Option<(u128, u8)> {
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
pub(crate) fn windows_icmp_ping(host: &str) -> Option<(u128, u8)> {
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
pub(crate) fn windows_icmp_ping(_host: &str) -> Option<(u128, u8)> {
    None
}

pub(crate) fn tcp_connect_latency(addresses: &[std::net::SocketAddr], timeout: Duration) -> Option<u128> {
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


pub(crate) fn run_tcp_ping_samples(addresses: &[std::net::SocketAddr], attempts: u8, timeout: Duration) -> (u8, Option<u128>, u8) {
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

#[cfg(target_os = "windows")]
pub(crate) fn active_tun_server_ip_for_ping(app: &AppHandle) -> Option<String> {
    let state = app.state::<AppState>();
    let connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    if !connected {
        return None;
    }

    state.runtime.lock().ok().and_then(|runtime_guard| {
        runtime_guard.as_ref().and_then(|runtime| {
            if runtime.network_mode.eq_ignore_ascii_case("tun") {
                runtime.tun_server_ip.clone()
            } else {
                None
            }
        })
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn add_temporary_direct_routes_for_ping(app: Option<&AppHandle>, addresses: &[std::net::SocketAddr]) -> Vec<String> {
    let Some(app) = app else {
        return Vec::new();
    };

    let Some(active_tun_server_ip) = active_tun_server_ip_for_ping(app) else {
        return Vec::new();
    };

    let default_route = match default_route_snapshot() {
        Ok(route) if !route.next_hop.trim().is_empty() && route.next_hop != "0.0.0.0" => route,
        _ => return Vec::new(),
    };

    let mut added_routes: Vec<String> = Vec::new();
    for address in addresses {
        let ip = match address.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(_) => continue,
        };

        if ip == active_tun_server_ip || added_routes.iter().any(|item| item == &ip) {
            continue;
        }

        // Во время активного TUN split-default отправляет все публичные IPv4 в Wintun.
        // Для проверки ping других VPN-нод временно добавляем /32 escape route через
        // физический gateway. Иначе зелёным обычно остаётся только текущий сервер.
        if route_add(&ip, "255.255.255.255", &default_route.next_hop, 2, None).is_ok() {
            added_routes.push(ip);
        }
    }

    added_routes
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn add_temporary_direct_routes_for_ping(_app: Option<&AppHandle>, _addresses: &[std::net::SocketAddr]) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_temporary_direct_routes_for_ping(added_routes: &[String]) {
    for ip in added_routes {
        route_delete(ip, "255.255.255.255", None, None);
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn cleanup_temporary_direct_routes_for_ping(_added_routes: &[String]) {}

pub(crate) fn server_ping_blocking(host: String, port: u16, app: Option<AppHandle>) -> Result<ConnectivityProbe, String> {
    let checked_at = unix_now_string();
    let normalized_host = normalize_socket_host(&host);
    if normalized_host.is_empty() {
        return Err("У выбранного сервера нет host для проверки пинга.".into());
    }

    let addresses = resolve_socket_addresses(&normalized_host, port)?;
    let temporary_direct_routes = add_temporary_direct_routes_for_ping(app.as_ref(), &addresses);
    let endpoint = format_endpoint_for_display(&normalized_host, port);

    // Для VPN-сервера важнее не ICMP, а доступность реального host:port.
    // Поэтому TCP-проверка идёт первой и с короткими timeout, чтобы UI не выглядел зависшим.
    let (success_count, latency_ms, packet_loss) = run_tcp_ping_samples(&addresses, 3, Duration::from_millis(850));
    if success_count > 0 {
        cleanup_temporary_direct_routes_for_ping(&temporary_direct_routes);
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
        cleanup_temporary_direct_routes_for_ping(&temporary_direct_routes);
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

    cleanup_temporary_direct_routes_for_ping(&temporary_direct_routes);

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
pub(crate) async fn server_ping(host: String, port: u16, app: AppHandle) -> Result<ConnectivityProbe, String> {
    tauri::async_runtime::spawn_blocking(move || server_ping_blocking(host, port, Some(app)))
        .await
        .map_err(|error| format!("Проверка пинга была прервана: {error}"))?
}

pub(crate) fn parse_xray_stat_value(raw: &str) -> Option<u64> {
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

pub(crate) fn query_xray_stat(core_path: &str, stat_name: &str) -> Result<u64, String> {
    let mut command = Command::new(core_path);
    command
        .arg("api")
        .arg("statsquery")
        .arg(format!("--server=127.0.0.1:{XRAY_API_PORT}"))
        .arg("-name")
        .arg(stat_name);

    let output = run_command_with_timeout(command, Duration::from_millis(1400), "xray api statsquery")?;
    // Xray can omit a stat until the first bytes pass through it. Treat a missing
    // value as zero instead of falling back to "unavailable", otherwise the UI
    // never starts showing proxy traffic on fresh connections.
    Ok(parse_xray_stat_value(&output).unwrap_or(0))
}

pub(crate) fn runtime_xray_stats_snapshot(state: &tauri::State<AppState>) -> Option<TrafficSnapshot> {
    if !tcp_port_open("127.0.0.1", XRAY_API_PORT, 120) {
        return None;
    }

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
pub(crate) fn windows_tun_traffic_snapshot() -> Option<TrafficSnapshot> {
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
pub(crate) fn windows_tun_traffic_snapshot() -> Option<TrafficSnapshot> {
    None
}

#[tauri::command]
pub(crate) async fn traffic_snapshot(app: AppHandle) -> Result<TrafficSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || traffic_snapshot_blocking(app))
        .await
        .map_err(|error| format!("Получение статистики трафика было прервано: {error}"))?
}

pub(crate) fn traffic_snapshot_blocking(app: AppHandle) -> Result<TrafficSnapshot, String> {
    let state = app.state::<AppState>();
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
pub(crate) fn parse_wmic_process_list(raw: &str) -> Vec<RunningAppInfo> {
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
pub(crate) fn split_csv_line(line: &str) -> Vec<String> {
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
pub(crate) fn parse_tasklist_process_list(raw: &str) -> Vec<RunningAppInfo> {
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
pub(crate) fn parse_powershell_process_list(raw: &str) -> Vec<RunningAppInfo> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    let rows = match parsed {
        Value::Array(items) => items,
        other @ Value::Object(_) => vec![other],
        _ => Vec::new(),
    };

    rows.into_iter()
        .filter_map(|item| {
            let pid = item.get("pid").and_then(Value::as_u64)? as u32;
            let name = item.get("name").and_then(Value::as_str).unwrap_or_default().trim().to_string();
            if name.is_empty() || !name.to_lowercase().ends_with(".exe") {
                return None;
            }

            let path = item
                .get("path")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
            let title = item
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);

            Some(RunningAppInfo { pid, name, path, title })
        })
        .collect()
}

#[cfg(target_os = "windows")]
pub(crate) fn dedupe_and_limit_running_apps(apps: Vec<RunningAppInfo>, limit: usize) -> Vec<RunningAppInfo> {
    let mut seen = std::collections::HashSet::<String>::new();
    let mut unique = apps
        .into_iter()
        .filter(|app| !app.name.trim().is_empty())
        .filter(|app| {
            let key = app
                .path
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.to_lowercase())
                .unwrap_or_else(|| format!("{}:{}", app.name.to_lowercase(), app.pid));
            seen.insert(key)
        })
        .collect::<Vec<_>>();

    unique.sort_by(|left, right| {
        let left_has_path = left.path.as_ref().map(|value| !value.is_empty()).unwrap_or(false);
        let right_has_path = right.path.as_ref().map(|value| !value.is_empty()).unwrap_or(false);
        let left_has_title = left.title.as_ref().map(|value| !value.is_empty()).unwrap_or(false);
        let right_has_title = right.title.as_ref().map(|value| !value.is_empty()).unwrap_or(false);

        right_has_title
            .cmp(&left_has_title)
            .then_with(|| right_has_path.cmp(&left_has_path))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.pid.cmp(&right.pid))
    });

    unique.truncate(limit);
    unique
}

#[cfg(target_os = "windows")]
pub(crate) fn list_running_apps_blocking() -> Result<Vec<RunningAppInfo>, String> {
    let powershell_script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentUser = $currentIdentity
if ($currentIdentity.Contains('\')) { $currentUser = $currentIdentity.Split('\', 2)[1] }
$currentSession = (Get-Process -Id $PID).SessionId
$seen = @{}
$items = New-Object System.Collections.Generic.List[object]
Get-CimInstance Win32_Process | ForEach-Object {
  $name = [string]$_.Name
  $isExe = -not [string]::IsNullOrWhiteSpace($name) -and $name.ToLowerInvariant().EndsWith('.exe')
  if ($isExe) {
    $ownerUser = ''
    try {
      $owner = $_ | Invoke-CimMethod -MethodName GetOwner
      if ($owner -and $owner.User) { $ownerUser = [string]$owner.User }
    } catch {}

    $sameUser = -not [string]::IsNullOrWhiteSpace($ownerUser) -and ($ownerUser -ieq $currentUser)
    $sameSession = $_.SessionId -eq $currentSession
    if ($sameUser -or $sameSession) {
      $path = [string]$_.ExecutablePath
      $title = ''
      try { $title = [string](Get-Process -Id $_.ProcessId -ErrorAction Stop).MainWindowTitle } catch {}

      $key = "$($_.ProcessId)|$name|$path"
      if (-not $seen.ContainsKey($key)) {
        $seen[$key] = $true
        $items.Add([PSCustomObject]@{
          pid = [UInt32]$_.ProcessId
          name = $name
          path = $path
          title = $title
        }) | Out-Null
      }
    }
  }
}
$items | Sort-Object @{Expression={ if ([string]::IsNullOrWhiteSpace($_.title)) { 1 } else { 0 } }}, name, pid | ConvertTo-Json -Compress -Depth 3
"#;

    let mut powershell = Command::new("powershell");
    powershell.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_script]);
    if let Ok(raw) = run_command_with_timeout(powershell, Duration::from_secs(7), "powershell user process list") {
        let apps = parse_powershell_process_list(&raw);
        if !apps.is_empty() {
            return Ok(dedupe_and_limit_running_apps(apps, 200));
        }
    }

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

    Ok(dedupe_and_limit_running_apps(apps, 200))
}

#[cfg(target_os = "windows")]
#[tauri::command]
pub(crate) async fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    tauri::async_runtime::spawn_blocking(list_running_apps_blocking)
        .await
        .map_err(|error| format!("Получение списка приложений было прервано: {error}"))?
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub(crate) async fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    Ok(Vec::new())
}

pub(crate) fn read_xray_version(app: &AppHandle) -> (String, Option<String>) {
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
pub(crate) fn read_windows_registry_value(key: &str, value_name: &str) -> Option<String> {
    let mut command = Command::new("reg");
    command.args(["query", key, "/v", value_name]);
    run_command_with_timeout(command, Duration::from_secs(4), &format!("reg query {value_name}"))
        .ok()
        .and_then(|raw| parse_reg_value(&raw, value_name))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_device_info() -> (String, String, String, String, String, String) {
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
pub(crate) fn windows_device_info() -> (String, String, String, String, String, String) {
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
pub(crate) fn native_app_info(app: AppHandle) -> NativeAppInfo {
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
pub(crate) fn pick_executable_path() -> Result<Option<String>, String> {
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
pub(crate) fn pick_executable_path() -> Result<Option<String>, String> {
    Ok(None)
}

#[tauri::command]
pub(crate) fn restart_application(app: AppHandle) -> Result<(), String> {
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
pub(crate) fn read_runtime_log(app: AppHandle, lines: Option<usize>) -> Result<Vec<String>, String> {
    tail_runtime_log(&app, lines.unwrap_or(20).clamp(1, 200))
}
