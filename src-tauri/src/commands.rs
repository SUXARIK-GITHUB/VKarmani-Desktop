use super::*;

fn write_interface_log_blocking(
    message: String,
    details: Option<String>,
    app: AppHandle,
) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_interface_event(&app, &line)
}

#[tauri::command]
pub(crate) async fn write_interface_log(
    message: String,
    details: Option<String>,
    app: AppHandle,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        write_interface_log_blocking(message, details, app)
    })
    .await
    .map_err(|error| format!("Запись interface-лога была прервана: {error}"))?
}

fn write_routing_log_blocking(
    message: String,
    details: Option<String>,
    app: AppHandle,
) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_runtime_event(&app, &line)
}

#[tauri::command]
pub(crate) async fn write_routing_log(
    message: String,
    details: Option<String>,
    app: AppHandle,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || write_routing_log_blocking(message, details, app))
        .await
        .map_err(|error| format!("Запись runtime-лога была прервана: {error}"))?
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
            return Err(format!(
                "HTTP inbound 127.0.0.1:{HTTP_PORT} не отвечает. Сначала запустите runtime."
            ));
        }

        let client = build_http_client(
            Some(&format!("http://127.0.0.1:{HTTP_PORT}")),
            Duration::from_secs(8),
        )?;
        return fetch_public_ip(&client);
    }

    let client = build_http_client(None, Duration::from_secs(4))?;
    fetch_public_ip(&client)
}

pub(crate) const CLIENT_STATE_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const SENSITIVE_CLIENT_STATE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const ENCRYPTED_STATE_MAX_BYTES: u64 = SENSITIVE_CLIENT_STATE_MAX_BYTES * 3;
pub(crate) const VKARMANI_ACCESS_KEY_PREFIX: &str = "https://sub.vkarmani.com/";

pub(crate) fn normalize_access_key_for_native(value: &str) -> Result<String, String> {
    if value.len() > 8192 {
        return Err("Ключ VKarmani превышает допустимый размер.".into());
    }
    let normalized = value.trim().to_string();
    if !normalized
        .to_ascii_lowercase()
        .starts_with(VKARMANI_ACCESS_KEY_PREFIX)
    {
        return Err("Ключ VKarmani должен начинаться с https://sub.vkarmani.com/.".to_string());
    }
    if normalized.len() < VKARMANI_ACCESS_KEY_PREFIX.len() + 5 {
        return Err("Ключ VKarmani выглядит слишком коротким.".to_string());
    }
    Ok(normalized)
}

pub(crate) fn is_allowed_client_state_key(key: &str) -> bool {
    matches!(
        key,
        "settings"
            | "splitTunnelEntries"
            | "favoriteServerIds"
            | "selectedServerId"
            | "lastKnownServers"
            | "sessionHistory"
    )
}

pub(crate) fn is_allowed_sensitive_client_state_key(key: &str) -> bool {
    matches!(key, "lastKnownServers")
}

// Cached legacy renderers may read, but cannot mutate v2 without CAS.
#[tauri::command]
pub(crate) async fn load_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<Option<String>, StateStorageError> {
    if !is_allowed_client_state_key(&key) {
        return Err(legacy_write_rejected());
    }
    let snapshot = load_state_snapshot(app).await?;
    Ok(snapshot
        .payload
        .public_state
        .get(&key)
        .map(Value::to_string))
}
#[tauri::command]
pub(crate) async fn load_sensitive_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<Option<String>, StateStorageError> {
    if !is_allowed_sensitive_client_state_key(&key) {
        return Err(legacy_write_rejected());
    }
    let snapshot = load_state_snapshot(app).await?;
    Ok(snapshot.payload.protected.get(&key).map(Value::to_string))
}
#[tauri::command]
pub(crate) async fn save_client_state_value(
    key: String,
    value: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let _ = (key, value, app);
    Err(legacy_write_rejected())
}
#[tauri::command]
pub(crate) async fn clear_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let _ = (key, app);
    Err(legacy_write_rejected())
}
#[tauri::command]
pub(crate) async fn save_sensitive_client_state_value(
    key: String,
    value: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let _ = (key, value, app);
    Err(legacy_write_rejected())
}
#[tauri::command]
pub(crate) async fn clear_sensitive_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let _ = (key, app);
    Err(legacy_write_rejected())
}
#[cfg(target_os = "windows")]
pub(crate) fn encrypt_access_key(value: &str) -> Result<String, String> {
    let mut input = DataBlob {
        cb_data: value.len() as u32,
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
        return Err(format!(
            "DPAPI CryptProtectData не смог зашифровать ключ: {}",
            std::io::Error::last_os_error()
        ));
    }

    let encrypted =
        unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
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
        return Err(format!(
            "DPAPI CryptUnprotectData не смог расшифровать ключ: {}",
            std::io::Error::last_os_error()
        ));
    }

    let decrypted =
        unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe {
        LocalFree(output.pb_data as *mut core::ffi::c_void);
    }

    String::from_utf8(decrypted)
        .map_err(|error| format!("DPAPI вернул не UTF-8 ключ доступа: {error}"))
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn encrypt_access_key(value: &str) -> Result<String, String> {
    let _ = value;
    Err("Защищённое хранилище требует Windows DPAPI; plaintext fallback запрещён.".into())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn decrypt_access_key(value: &str) -> Result<String, String> {
    let _ = value;
    Err("Защищённое хранилище требует Windows DPAPI; plaintext fallback запрещён.".into())
}

pub(crate) fn load_access_key_secure_blocking(app: AppHandle) -> Result<Option<String>, String> {
    app_durable_store(&app)
        .and_then(|store| store.load())
        .map(|snapshot| snapshot.payload.access_key)
        .map_err(|error| format!("{}: {}", error.code, error.message))
}
#[tauri::command]
pub(crate) async fn save_access_key_secure(
    value: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let _ = (value, app);
    Err(legacy_write_rejected())
}
#[tauri::command]
pub(crate) async fn clear_access_key_secure(app: AppHandle) -> Result<(), StateStorageError> {
    let _ = app;
    Err(legacy_write_rejected())
}
#[tauri::command]
pub(crate) async fn load_access_key_secure(
    app: AppHandle,
) -> Result<Option<String>, StateStorageError> {
    Ok(load_state_snapshot(app).await?.payload.access_key)
}
#[tauri::command]
pub(crate) fn bootstrap_info() -> BootstrapInfo {
    BootstrapInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
    }
}

pub(crate) fn clear_native_session_authorization(
    state: &tauri::State<AppState>,
) -> Result<(), String> {
    let mut authorization = state
        .session_authorization
        .lock()
        .map_err(|_| "Не удалось очистить native-сессию.".to_string())?;
    state
        .authorization_generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    *authorization = None;
    *state
        .session_authorized
        .lock()
        .map_err(|_| "Не удалось обновить состояние авторизации.".to_string())? = false;
    Ok(())
}

pub(crate) fn ensure_native_session_authorized(
    app: &AppHandle,
    state: &tauri::State<AppState>,
) -> Result<(), String> {
    let is_authorized = *state
        .session_authorized
        .lock()
        .map_err(|_| "Не удалось проверить состояние авторизации.".to_string())?;
    if !is_authorized {
        return Err("SESSION_UNAUTHORIZED: Сначала войдите по ключу VKarmani, затем запускайте подключение.".into());
    }

    authorize_native_subscription(app, state, false, None)
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

fn set_session_authorized_blocking(
    authorized: bool,
    access_key: Option<String>,
    state: tauri::State<AppState>,
    app: AppHandle,
    requested_generation: Option<u64>,
) -> Result<bool, String> {
    if authorized {
        // Native-сессия больше не доверяет одному только renderer-состоянию.
        // Перед включением нативных команд подключения берём ключ из DPAPI и,
        // если renderer всё же передал ключ, требуем полного совпадения.
        let stored_access_key = load_access_key_secure_blocking(app.clone())?
            .ok_or_else(|| "Native-сессия не подтверждена: ключ не найден в защищённом хранилище Windows. Войдите по ключу ещё раз.".to_string())?;
        let stored_access_key_hash = sha256_hex_bytes(stored_access_key.as_bytes());

        if let Some(provided_access_key) = access_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let normalized_provided_access_key =
                normalize_access_key_for_native(provided_access_key)?;
            let provided_hash = sha256_hex_bytes(normalized_provided_access_key.as_bytes());
            if provided_hash != stored_access_key_hash {
                clear_native_session_authorization(&state)?;
                return Err("Native-сессия не подтверждена: ключ renderer не совпадает с защищённым DPAPI-хранилищем.".to_string());
            }
        }

        let needs_initial_verification = state
            .session_authorization
            .lock()
            .map_err(|_| "Не удалось проверить native-сессию.".to_string())?
            .is_none();
        authorize_native_subscription(
            &app,
            &state,
            needs_initial_verification,
            requested_generation,
        )?;
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
pub(crate) async fn set_session_authorized(
    authorized: bool,
    access_key: Option<String>,
    app: AppHandle,
) -> Result<bool, String> {
    let generation = app
        .state::<AppState>()
        .authorization_generation
        .load(std::sync::atomic::Ordering::Acquire);
    if !authorized {
        clear_native_session_authorization(&app.state::<AppState>())?;
        refresh_tray_menu(&app);
        return Ok(false);
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        set_session_authorized_blocking(
            authorized,
            access_key,
            state,
            app.clone(),
            Some(generation),
        )
    })
    .await
    .map_err(|_| "Проверка native-сессии прервана.".to_string())?
}

#[tauri::command]
pub(crate) async fn runtime_observation(app: AppHandle) -> Result<RuntimeStatus, String> {
    // Connection recovery must not use the UI refresh coalescer (which may
    // return no snapshot), nor runtime_status's liveness/recovery side effects.
    tauri::async_runtime::spawn_blocking(move || read_runtime_status(&app, app.state::<AppState>()))
        .await
        .map_err(|_| "RUNTIME_OBSERVATION_UNAVAILABLE".into())
}
#[tauri::command]
pub(crate) async fn diagnostics_snapshot(
    app: AppHandle,
) -> Result<crate::diagnostic_facts::DiagnosticSnapshot, String> {
    let permit = DiagnosticReadPermit::acquire()?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        crate::diagnostic_facts::collect(&app, app.state::<AppState>())
    })
    .await
    .map_err(|_| "DIAGNOSTICS_READ_FAILED".to_string())
}

static DIAGNOSTICS_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
struct DiagnosticReadPermit;
impl DiagnosticReadPermit {
    fn acquire() -> Result<Self, String> {
        DIAGNOSTICS_IN_FLIGHT
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map(|_| Self)
            .map_err(|_| "DIAGNOSTICS_BUSY".into())
    }
}
impl Drop for DiagnosticReadPermit {
    fn drop(&mut self) {
        DIAGNOSTICS_IN_FLIGHT.store(false, std::sync::atomic::Ordering::Release);
    }
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
        check_current_operation(state)?;
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
                &format!(
                    "Xray-core завершился сразу после старта. Exit code: {:?}",
                    code
                ),
            );

            if joined_excerpt.to_ascii_lowercase().contains("wintun.dll") {
                return Err(format!(
                    "CORE_EXITED_EARLY: Xray-core не смог запустить TUN: отсутствует или не загружается wintun.dll рядом с xray.exe. Проверьте {}.",
                    core_working_dir.display()
                ));
            }

            if !joined_excerpt.is_empty() {
                return Err(format!(
                    "CORE_EXITED_EARLY: Xray-core завершился сразу после запуска. Exit code: {:?}. Последние строки xray-runtime.log: {}",
                    code,
                    joined_excerpt
                ));
            }

            return Err(format!(
                "CORE_EXITED_EARLY: Xray-core завершился сразу после запуска. Exit code: {:?}. Проверьте xray-runtime.log.",
                code
            ));
        }

        let owned_ready = owned_runtime_ports_ready(child)?;
        let ports_state = format!("ownedListeners={owned_ready}");

        if owned_ready {
            let _ =
                append_runtime_event(app, &format!("Xray локальные порты готовы: {ports_state}."));
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
                "CORE_PORT_TIMEOUT: Xray запущен, но локальные порты не стали готовы за {} мс ({ports_state}). {details}",
                timeout.as_millis()
            ));
        }

        std::thread::sleep(Duration::from_millis(90));
    }
}

#[tauri::command]
#[expect(
    clippy::too_many_arguments,
    reason = "Existing Tauri named-argument IPC contract; grouping fields would break the frontend wire API"
)]
pub(crate) async fn request_connect(
    server_id: String,
    server_label: String,
    server_fingerprint: Option<String>,
    runtime_template: Value,
    canonical_template_json: String,
    network_mode: Option<String>,
    tun_routing_mode: Option<String>,
    ip_stack: Option<String>,
    reconnect: Option<bool>,
    split_tunnel_entries: Option<Vec<SplitTunnelEntryPayload>>,
    routing_exclusions: Option<RoutingExclusionSettingsPayload>,
    app: AppHandle,
) -> Result<RuntimeStatus, NativeFailure> {
    let (runtime_template, verified_fingerprint) = verified_template_identity(
        &runtime_template,
        &canonical_template_json,
        server_fingerprint.as_deref(),
    )
    .map_err(|e| NativeFailure::from_error(&e, RuntimeCommand::Connect))?;
    let requested_generation = app
        .state::<AppState>()
        .operation_generation
        .load(std::sync::atomic::Ordering::Acquire);
    let result = tauri::async_runtime::spawn_blocking(move || {
        request_connect_blocking(ConnectRequest {
            server_id,
            server_label,
            server_fingerprint: Some(verified_fingerprint),
            runtime_template,
            network_mode,
            tun_routing_mode,
            ip_stack,
            reconnect,
            split_tunnel_entries,
            routing_exclusions,
            app,
            requested_generation,
        })
    })
    .await
    .map_err(|_| NativeFailure::task_failed())?;
    result.map_err(|e| NativeFailure::from_error(&e, RuntimeCommand::Connect))
}

pub(crate) fn validate_xray_config_with_core(
    core_path: &Path,
    config_path: &Path,
    expected_config_hash: &str,
) -> Result<(), String> {
    let integrity = prepare_core_launch(core_path, Some((config_path, expected_config_hash)))?;
    let core_path = integrity.core.as_path();
    let config_path = integrity
        .config
        .as_deref()
        .ok_or("CONFIG_PROVENANCE_MISSING")?;
    let core_working_dir = core_path.parent().ok_or_else(|| {
        "Не удалось определить рабочую папку Xray-core для проверки config.".to_string()
    })?;

    let mut command = Command::new(core_path);
    command
        .current_dir(core_working_dir)
        .env("XRAY_LOCATION_ASSET", core_working_dir)
        .env(
            "XRAY_LOCATION_CONFIG",
            config_path.parent().unwrap_or(core_working_dir),
        )
        .arg("run")
        .arg("-test")
        .arg("-config")
        .arg(config_path)
        .stdin(Stdio::null());

    run_command_with_timeout(command, Duration::from_secs(8), "xray config test")
        .map(|_| ())
        .map_err(|error| crate::native_error::config_validation_error(&error))
}

pub(crate) fn validate_config_projection(
    core: &Path,
    config_path: &Path,
    config: &Value,
) -> Result<(), String> {
    let projection = config_preflight_projection(config)?;
    let bytes = serde_json::to_vec(&projection).map_err(|_| "CONFIG_PREFLIGHT_SERIALIZE")?;
    let path = config_path.with_extension("preflight.json");
    let parents = lock_runtime_parent_paths(&path)?;
    write_new_runtime_config(&path, &bytes)?;
    struct Prepared {
        path: PathBuf,
        hash: String,
        _parents: Vec<File>,
    }
    impl Drop for Prepared {
        fn drop(&mut self) {
            // Never remove a replaced/unknown file as a successful cleanup.
            if read_verified_runtime_config(&self.path, &self.hash).is_ok() {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
    let prepared = Prepared {
        path,
        hash: sha256_hex_bytes(&bytes),
        _parents: parents,
    };
    validate_xray_config_with_core(core, &prepared.path, &prepared.hash)
}

fn remove_startup_runtime_config(app: &AppHandle, config_path: &Path, reason: &str) {
    if fs::remove_file(config_path).is_ok() {
        let _ = append_runtime_event(
            app,
            &format!("Временный Xray runtime config удалён после ошибки старта ({reason})."),
        );
    }
}

struct ConnectRequest {
    server_id: String,
    server_label: String,
    server_fingerprint: Option<String>,
    runtime_template: RuntimeTemplate,
    network_mode: Option<String>,
    tun_routing_mode: Option<String>,
    ip_stack: Option<String>,
    reconnect: Option<bool>,
    split_tunnel_entries: Option<Vec<SplitTunnelEntryPayload>>,
    routing_exclusions: Option<RoutingExclusionSettingsPayload>,
    app: AppHandle,
    requested_generation: u64,
}

fn request_connect_blocking(request: ConnectRequest) -> Result<RuntimeStatus, String> {
    let ConnectRequest {
        server_id,
        server_label,
        server_fingerprint,
        runtime_template,
        network_mode,
        tun_routing_mode,
        ip_stack,
        reconnect,
        split_tunnel_entries,
        routing_exclusions,
        app,
        requested_generation,
    } = request;
    // Reject malformed supplied modes before authorization/storage reads,
    // operation admission or core discovery. TUN requires an explicit policy;
    // missing non-policy legacy fields keep their defaults.
    let mode = NetworkMode::parse(network_mode.as_deref())?;
    let normalized_network_mode = mode.as_str().to_string();
    let policy_mode = mode
        .require_process_enforcement(tun_routing_mode.as_deref())
        .map_err(|error| crate::native_error::ConnectStage::Preflight.wrap(&error))?;
    let normalized_ip_stack = NetworkIpStack::parse(ip_stack.as_deref())?
        .as_str()
        .to_string();
    if normalized_network_mode == "tun" && normalized_ip_stack == "ipv6" {
        return Err("TUN_IPV6_UNSUPPORTED: IPv6 режим сейчас доступен только для Proxy. TUN оставлен IPv4-only, чтобы не получить IPv6 loop/leak при переключении маршрутов Windows. Выберите IPv4 или используйте Proxy режим.".into());
    }
    let state = app.state::<AppState>();
    if state
        .stop_requested
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err("OPERATION_CANCELLED: отключение ещё выполняется.".into());
    }
    ensure_native_session_authorized(&app, &state)?;

    if runtime_template.family.to_lowercase() != "xray" {
        return Err("Сейчас поддерживается только Xray runtime family.".into());
    }
    validate_runtime_template(&runtime_template)?;
    let mut _operation_guard =
        begin_open_runtime_operation(&state, Duration::from_secs(8), "connect")?;
    if state
        .operation_generation
        .load(std::sync::atomic::Ordering::Acquire)
        != requested_generation
    {
        return Err("OPERATION_CANCELLED: подключение отменено до изменения runtime.".into());
    }

    let core_path = resolve_core_path(&app).ok_or_else(|| core_not_found_message(&app))?;
    ensure_core_launchable(&core_path)?;

    let reconnect_requested = reconnect.unwrap_or(false);

    let stored_entries = split_tunnel_entries.unwrap_or_default();
    let active_split_tunnel_entries = if normalized_network_mode == "tun" {
        active_policy_entries(&stored_entries, policy_mode)
            .map_err(|e| format!("CONNECT_PREFLIGHT: {e}"))?
    } else {
        vec![]
    };

    let (outbound_host, outbound_port) = extract_outbound_address_and_port(&runtime_template);

    if normalized_network_mode == "tun"
        && outbound_host
            .as_deref()
            .map(|value| value.trim())
            .unwrap_or_default()
            .is_empty()
    {
        return Err("TUN режим не может стартовать: в runtime-конфиге не удалось определить адрес VPN-сервера. Выберите другой сервер или используйте Proxy режим.".into());
    }

    #[cfg(target_os = "windows")]
    if normalized_network_mode == "tun" {
        NetworkMode::Tun.require_elevation(is_process_elevated()?)?;
    }

    let request_hash = sha256_hex_bytes(
        serde_json::to_string(&json!({
            "templateHash": server_fingerprint, "mode": normalized_network_mode,
            "ipStack": normalized_ip_stack, "policyMode": policy_mode, "policies": active_split_tunnel_entries,
            "exclusions": routing_exclusions,
        }))
        .map_err(|_| "Не удалось вычислить request identity".to_string())?
        .as_bytes(),
    );
    let already_active = !reconnect_requested
        && state
            .runtime
            .lock()
            .map(|mut runtime| {
                runtime.as_mut().is_some_and(|runtime| {
                    runtime.server_id == server_id
                        && runtime.request_hash == request_hash
                        && matches!(runtime.child.try_wait(), Ok(None))
                })
            })
            .unwrap_or(false);
    if already_active {
        _operation_guard.commit();
        drop(_operation_guard);
        return Ok(build_runtime_status(&app, state));
    }

    let prepared_policy = if normalized_network_mode == "tun" {
        Some(
            build_split_tunnel_rule_plan_for_mode(&active_split_tunnel_entries, policy_mode)
                .map_err(|error| format!("CONNECT_PREFLIGHT: {error}"))?,
        )
    } else {
        None
    };

    // Pure adapters and read-only physical/service discovery finish before stopping the old runtime.
    let outbound_ips = outbound_host
        .as_deref()
        .map(|host| resolve_ipv4_addresses(host, outbound_port))
        .unwrap_or_default();
    let outbound_ip_display = if outbound_ips.is_empty() {
        "—".to_string()
    } else {
        outbound_ips.join(",")
    };
    #[cfg(target_os = "windows")]
    let physical_route = if normalized_network_mode == "tun" {
        Some(default_route_snapshot().map_err(|error| format!("CONNECT_PREFLIGHT: {error}"))?)
    } else {
        None
    };
    #[cfg(target_os = "windows")]
    let send_through_ip = physical_route.as_ref().map(|route| route.source_ip.clone());
    #[cfg(not(target_os = "windows"))]
    let send_through_ip: Option<String> = None;
    #[cfg(not(target_os = "windows"))]
    let physical_route: Option<DefaultRouteSnapshot> = None;

    if normalized_network_mode == "tun" && outbound_ips.is_empty() {
        return Err(format!(
            "CONNECT_PREFLIGHT: TUN режим пока поддерживает только серверы с IPv4 endpoint. Для сервера {} не удалось получить IPv4 адрес. Выберите другой сервер или используйте Proxy режим.",
            outbound_host.as_deref().unwrap_or("—")
        ));
    }

    if normalized_network_mode == "tun" && send_through_ip.is_none() {
        return Err("CONNECT_PREFLIGHT: Не удалось определить локальный IPv4 адрес активного сетевого адаптера для TUN режима. Подключитесь к сети без VPN/виртуального адаптера и попробуйте снова.".into());
    }

    let output_dir = runtime_output_dir(&app)?;
    let _ = cleanup_runtime_config_files(&app);
    let config_path = output_dir.join(format!(
        "xray-config-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let runtime_trace_path = runtime_log_path(&app)?;
    let log_path = runtime_trace_path.clone();

    let (mut config, split_tunnel_plan, routing_exclusion_plan) = build_xray_config_with_plan(
        &runtime_template,
        &normalized_network_mode,
        &normalized_ip_stack,
        send_through_ip.as_deref(),
        prepared_policy,
        routing_exclusions.as_ref(),
        Some(runtime_trace_path.as_path()),
    )
    .map_err(|error| {
        crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::Preflight,
            &normalized_network_mode,
            &error,
            None,
        )
    })?;

    #[cfg(target_os = "windows")]
    if let Some(route) = physical_route.as_ref() {
        bind_tun_outbounds(&mut config, &route.interface_alias)
            .map_err(|error| format!("CONNECT_PREFLIGHT: {error}"))?;
    }

    let config_text = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Не удалось сериализовать config: {error}"))?;
    let config_hash = sha256_hex_bytes(config_text.as_bytes());
    _operation_guard.check()?;
    // Reject invalid provider transports/config while the prior runtime is
    // still alive. Never construct a second TUN during this preflight.
    validate_config_projection(&core_path, &config_path, &config).map_err(|error| {
        crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::Preflight,
            &normalized_network_mode,
            &error,
            None,
        )
    })?;
    _operation_guard.check()?;
    if let Some(expected) = physical_route.as_ref() {
        require_physical_binding(expected, current_physical_binding())?;
    }
    _operation_guard.stage("stopping")?;
    stop_managed_or_starting_runtime(
        &app,
        &state,
        !reconnect_requested || normalized_network_mode == "tun",
        "connect_preflight",
    )?;
    let config_written = std::cell::Cell::new(false);
    let mut failed_connect = FailedConnectRollback::new(|| {
        crate::diagnostic_facts::record_pending_failure_if_missing(
            &app,
            &normalized_network_mode,
            None,
        );
        let _ = restore_saved_proxy_state(&app, &state, "connect_failed_after_stop");
        if config_written.get() {
            remove_startup_runtime_config(&app, &config_path, "connect_failed_after_stop");
        }
        if let Ok(mut connected) = state.connected.lock() {
            *connected = false;
        }
        if let Ok(mut label) = state.active_server_label.lock() {
            *label = None;
        }
    });
    if let Err(first_release_error) = wait_for_runtime_ports_release(if reconnect_requested {
        Duration::from_secs(6)
    } else {
        Duration::from_secs(4)
    }) {
        let _ = append_runtime_event(
            &app,
            &format!("Локальные порты не освободились с первой попытки, выполняю повторную очистку Xray перед стартом нового сервера: {first_release_error}"),
        );
        wait_for_runtime_ports_release(Duration::from_secs(4)).map_err(|second_release_error| {
            crate::diagnostic_facts::record_connect_failure(
                &app,
                crate::native_error::ConnectStage::PortRelease,
                &normalized_network_mode,
                &format!("CORE_PORT_CONFLICT: {first_release_error}; {second_release_error}"),
                None,
            )
        })?;
    }
    if reconnect_requested {
        let _ = append_runtime_event(&app, "Старый Xray остановлен, локальные порты освобождены, запускаем выбранный сервер без наложения процессов.");
    }
    ensure_runtime_ports_available().map_err(|error| {
        crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::PortRelease,
            &normalized_network_mode,
            &error,
            None,
        )
    })?;

    validate_or_create_log(&runtime_trace_path).map_err(|error| format!("CONNECT_LOG: {error}"))?;
    _operation_guard.stage("validating")?;
    write_new_runtime_config(&config_path, config_text.as_bytes())
        .map_err(|error| format!("Не удалось записать config: {error}"))?;
    config_written.set(true);

    validate_xray_config_with_core(&core_path, &config_path, &config_hash).map_err(|error| {
        let error = crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::ConfigValidation,
            &normalized_network_mode,
            &error,
            None,
        );
        let _ = append_runtime_event(&app, &error);
        remove_startup_runtime_config(&app, &config_path, "config_validation_failed");
        error
    })?;
    if let Err(error) = _operation_guard.check() {
        remove_startup_runtime_config(&app, &config_path, "operation_cancelled");
        return Err(error);
    }

    if normalized_network_mode == "tun" {
        let core_dir = core_path.parent().map(|value| value.to_path_buf());
        let geoip_status = core_dir
            .as_ref()
            .map(|dir| {
                let path = dir.join("geoip.dat");
                if !path.exists() {
                    "нет файла".to_string()
                } else {
                    verify_core_manifest_artifact(&path, "geoip.dat")
                        .map(|_| "ok".to_string())
                        .unwrap_or_else(|error| error)
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
                    verify_core_manifest_artifact(&path, "geosite.dat")
                        .map(|_| "ok".to_string())
                        .unwrap_or_else(|error| error)
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
                    validate_core_sidecar_path(&path, "wintun.dll")
                        .map(|_| "ok".to_string())
                        .unwrap_or_else(|error| error)
                }
            })
            .unwrap_or_else(|| "не удалось определить папку core".to_string());
        let wintun_exists = wintun_status == "ok";
        let _ = append_runtime_event(
            &app,
            &format!(
                "TUN diagnostics: core={} | config={} | runtimeLog={} | geoip.dat={} | geosite.dat={} | wintun.dll={} | outboundHost={} | outboundIPv4={} | sendThrough={}",
                core_path.display(),
                config_path.display(),
                log_path.display(),
                geoip_status,
                geosite_status,
                wintun_status,
                outbound_host.as_deref().unwrap_or("—"),
                outbound_ip_display.as_str(),
                send_through_ip.as_deref().unwrap_or("—")
            ),
        );
        let _ = append_runtime_event(
            &app,
            &format!(
                "TUN physical interface binding: {} IPv4 endpoint(s): {}; no global endpoint /32 routes.",
                outbound_ips.len(),
                outbound_ip_display.as_str()
            ),
        );

        if !wintun_exists {
            remove_startup_runtime_config(&app, &config_path, "wintun_missing_or_invalid");
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

    if !routing_exclusion_plan.domain_rules.is_empty()
        || !routing_exclusion_plan.ip_rules.is_empty()
    {
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

    let core_working_dir = match core_path.parent() {
        Some(dir) => dir,
        None => {
            remove_startup_runtime_config(&app, &config_path, "core_working_dir_missing");
            return Err(
                "Не удалось определить рабочую папку Xray-core для запуска runtime.".to_string(),
            );
        }
    };

    _operation_guard.stage("starting")?;
    let child = match spawn_xray_runtime_child(&core_path, &config_path, &log_path, &config_hash) {
        Ok(child) => child,
        Err(error) => {
            let error = crate::diagnostic_facts::record_connect_failure(
                &app,
                crate::native_error::ConnectStage::Spawn,
                &normalized_network_mode,
                &error,
                None,
            );
            remove_startup_runtime_config(&app, &config_path, "xray_spawn_failed");
            return Err(error);
        }
    };
    let mut child = PendingXray::new(
        child,
        app.clone(),
        config_path.clone(),
        normalized_network_mode.clone(),
        outbound_ips.clone(),
    );
    let child_pid = child.id();
    remember_starting_runtime(
        &state,
        StartingCore {
            pid: child_pid,
            config_hash: config_hash.clone(),
        },
    );

    if let Err(error) = wait_for_xray_runtime_ready(
        &app,
        &state,
        &mut child,
        &log_path,
        core_working_dir,
        &normalized_network_mode,
    ) {
        let error = crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::Listeners,
            &normalized_network_mode,
            &error,
            Some(&mut child),
        );
        let _ = append_runtime_event(
            &app,
            &format!(
                "Xray runtime не стал готовым после запуска, выполняю аварийную очистку: {error}"
            ),
        );
        clear_starting_runtime(&state, child_pid);
        let _ = cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &outbound_ips);
        let _ = restore_saved_proxy_state(&app, &state, "connect_readiness_failed");
        let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
        remove_startup_runtime_config(&app, &config_path, "runtime_readiness_failed");
        return Err(error);
    }

    if normalized_network_mode == "tun" {
        _operation_guard.stage("configuring-routes")?;
        if let Some(expected) = physical_route.as_ref() {
            require_physical_binding(expected, current_physical_binding())?;
        }
        let mut observed_error = None;
        configure_tun_routes_observed(&app, TUN_INTERFACE_NAME, &outbound_ips, |error| {
            observed_error = Some(crate::diagnostic_facts::record_connect_failure(
                &app,
                crate::native_error::ConnectStage::Routes,
                &normalized_network_mode,
                error,
                Some(&mut child),
            ));
        })
        .map_err(|error| {
            let error = observed_error.unwrap_or_else(|| {
                crate::diagnostic_facts::record_connect_failure(
                    &app,
                    crate::native_error::ConnectStage::Routes,
                    &normalized_network_mode,
                    &error,
                    Some(&mut child),
                )
            });
            clear_starting_runtime(&state, child_pid);
            let _ = cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &outbound_ips);
            let _ = restore_saved_proxy_state(&app, &state, "tun_routes_failed");
            let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
            remove_startup_runtime_config(&app, &config_path, "tun_routes_failed");
            crate::native_error::contextual_runtime_error(
                &error,
                "Не удалось подготовить Windows-маршруты для TUN режима",
            )
        })?;
        let _ = append_runtime_event(
            &app,
            &format!("Owned IPv4/IPv6 split routes applied; default policy={}; explicit DIRECT exclusions retained.", if split_tunnel_plan.default_vpn { "VPN" } else { "DIRECT" }),
        );
        std::thread::sleep(Duration::from_millis(250));
        let _ = append_runtime_event(
            &app,
            "TUN маршруты применены и стабилизированы для текущего сеанса.",
        );
    }

    if let Some(status) = child.try_wait().map_err(|error| {
        format!("Не удалось проверить Xray перед завершением подключения: {error}")
    })? {
        let failure = crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::Publish,
            &normalized_network_mode,
            "CORE_EXITED_EARLY",
            Some(&mut child),
        );
        clear_starting_runtime(&state, child_pid);
        let code = status.code();
        if let Ok(mut exit_guard) = state.last_exit_code.lock() {
            *exit_guard = code;
        }
        let _ = cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &outbound_ips);
        let _ = restore_saved_proxy_state(&app, &state, "connect_final_check_failed");
        remove_startup_runtime_config(&app, &config_path, "xray_stopped_before_ready_final_check");
        return Err(failure);
    }

    if let Some(expected) = physical_route.as_ref() {
        require_physical_binding(expected, current_physical_binding())
            .and_then(|_| confirm_tun_routes_ready(&app))
            .map_err(|error| {
                crate::diagnostic_facts::record_connect_failure(
                    &app,
                    crate::native_error::ConnectStage::Publish,
                    &normalized_network_mode,
                    &error,
                    Some(&mut child),
                )
            })?;
    }
    if !owned_runtime_ports_ready(&mut child).map_err(|error| {
        crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::Publish,
            &normalized_network_mode,
            &error,
            Some(&mut child),
        )
    })? {
        return Err(crate::diagnostic_facts::record_connect_failure(
            &app,
            crate::native_error::ConnectStage::Publish,
            &normalized_network_mode,
            "CORE_PORT_TIMEOUT: runtime listeners lost before publication",
            Some(&mut child),
        ));
    }
    _operation_guard.stage("publishing")?;

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = Some(server_label.clone());
    }

    if let Ok(mut exit_guard) = state.last_exit_code.lock() {
        *exit_guard = None;
    }

    {
        let mut runtime_guard = state
            .runtime
            .lock()
            .map_err(|_| "Не удалось опубликовать Xray runtime.".to_string())?;
        *runtime_guard = Some(ManagedCore {
            child: child.commit(),
            core_path: core_path.to_string_lossy().to_string(),
            config_path: config_path.to_string_lossy().to_string(),
            config_hash,
            request_hash,
            log_path: log_path.to_string_lossy().to_string(),
            server_id: server_id.clone(),
            server_fingerprint: server_fingerprint
                .clone()
                .filter(|value| !value.trim().is_empty()),
            started_at: unix_now_string(),
            telemetry_epoch: next_telemetry_epoch(),
            network_mode: normalized_network_mode.clone(),
            tun_routing_mode: if normalized_network_mode == "tun" {
                Some(policy_mode.to_owned())
            } else {
                None
            },
            tun_interface_name: if normalized_network_mode == "tun" {
                Some(TUN_INTERFACE_NAME.to_string())
            } else {
                None
            },
            tun_server_ips: if normalized_network_mode == "tun" {
                outbound_ips.clone()
            } else {
                Vec::new()
            },
            self_restart_count: 0,
            last_self_restart_at: None,
            physical_binding: physical_route,
        });
    }
    if let Ok(mut guard) = state.connected.lock() {
        *guard = true;
    }

    clear_starting_runtime(&state, child_pid);
    failed_connect.commit();

    let _ = app.emit("vkarmani://native-connect", server_id);
    let _ = app.emit("vkarmani://native-status", server_label);
    refresh_tray_menu(&app);

    _operation_guard.commit();
    drop(_operation_guard);
    Ok(build_runtime_status(&app, app.state::<AppState>()))
}

#[tauri::command]
pub(crate) async fn rollback_failed_connect(
    expected_config_path: String,
    app: AppHandle,
) -> Result<RuntimeStatus, NativeFailure> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let mut operation =
            acquire_operation_lock(&state, Duration::from_secs(6), "failed-connect-rollback")?;
        {
            let runtime = state
                .runtime
                .lock()
                .map_err(|_| "Runtime state повреждён")?;
            require_runtime_config_identity(
                runtime.as_ref().map(|runtime| runtime.config_path.as_str()),
                &expected_config_path,
            )?;
        }
        // Ownership is checked BEFORE cancellation flags, generation or network state.
        operation.stage("stopping")?;
        stop_managed_or_starting_runtime(&app, &state, true, "failed-connect-rollback")?;
        restore_saved_proxy_state(&app, &state, "failed-connect-rollback")?;
        operation.commit();
        drop(operation);
        Ok(build_runtime_status(&app, app.state::<AppState>()))
    })
    .await
    .map_err(|_| NativeFailure::task_failed())?;
    result.map_err(|e: String| NativeFailure::from_error(&e, RuntimeCommand::Rollback))
}

#[tauri::command]
pub(crate) async fn request_disconnect(app: AppHandle) -> Result<RuntimeStatus, NativeFailure> {
    app.state::<AppState>()
        .stop_requested
        .store(true, std::sync::atomic::Ordering::Release);
    app.state::<AppState>()
        .operation_generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let result = tauri::async_runtime::spawn_blocking(move || request_disconnect_blocking(app))
        .await
        .map_err(|_| NativeFailure::task_failed())?;
    result.map_err(|e: String| NativeFailure::from_error(&e, RuntimeCommand::Disconnect))
}

pub(crate) fn request_disconnect_blocking(app: AppHandle) -> Result<RuntimeStatus, String> {
    let state = app.state::<AppState>();
    state
        .stop_requested
        .store(true, std::sync::atomic::Ordering::Release);
    state
        .operation_generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let mut operation = begin_runtime_operation(
        &state,
        Duration::from_secs(18),
        "disconnect",
        Duration::from_secs(20),
    )?;
    operation.stage("stopping")?;
    stop_managed_or_starting_runtime(&app, &state, true, "user_disconnect")?;
    restore_saved_proxy_state(&app, &state, "user_disconnect")?;
    cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &[])?;
    let _ = cleanup_runtime_config_files(&app);

    if let Ok(mut guard) = state.connected.lock() {
        *guard = false;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = None;
    }

    let _ = append_runtime_event(&app, "Xray runtime остановлен пользователем.");
    let _ = app.emit("vkarmani://native-disconnect", "idle");
    refresh_tray_menu(&app);
    operation.commit();
    state
        .stop_requested
        .store(false, std::sync::atomic::Ordering::Release);
    drop(operation);
    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
pub(crate) fn cache_profile_sync(
    profile_count: usize,
    source: String,
    state: tauri::State<AppState>,
    app: AppHandle,
) {
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
    window
        .minimize()
        .map_err(|error| format!("Не удалось свернуть окно: {error}"))
}

#[tauri::command]
pub(crate) fn window_toggle_maximize(
    window: tauri::WebviewWindow,
    app: AppHandle,
) -> Result<(), String> {
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
    window
        .close()
        .map_err(|error| format!("Не удалось закрыть окно: {error}"))
}

#[tauri::command]
pub(crate) fn window_hide(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно скрыто в трей.");
    window
        .hide()
        .map_err(|error| format!("Не удалось скрыть окно: {error}"))
}

fn validate_external_url(raw_url: &str) -> Result<String, String> {
    let parsed =
        reqwest::Url::parse(raw_url).map_err(|_| "Некорректная внешняя ссылка.".to_string())?;

    if parsed.scheme() != "https" {
        return Err("Открывать можно только HTTPS-ссылки.".to_string());
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Внешние ссылки с userinfo запрещены.".to_string());
    }

    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let allowed = matches!(
        host.as_str(),
        "t.me" | "telegram.me" | "vkarmani.com" | "www.vkarmani.com"
    );

    if !allowed {
        return Err(
            "Эта внешняя ссылка не входит в список разрешённых VKarmani-ссылок.".to_string(),
        );
    }

    Ok(parsed.to_string())
}

fn open_external_url_blocking(url: String) -> Result<(), String> {
    let safe_url = validate_external_url(&url)?;

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        let target: Vec<u16> = safe_url.encode_utf16().chain(Some(0)).collect();
        // One URL document argument, no command interpreter or parameter expansion.
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                target.as_ptr(),
                null(),
                null(),
                1,
            )
        } as isize;
        if result <= 32 {
            return Err(format!("Не удалось открыть браузер: ShellExecute {result}"));
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(safe_url.as_str())
            .spawn()
            .map_err(|error| format!("Не удалось открыть ссылку в браузере: {error}"))?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(safe_url.as_str())
            .spawn()
            .map_err(|error| format!("Не удалось открыть ссылку в браузере: {error}"))?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err("Открытие внешних ссылок не поддерживается на этой платформе.".to_string())
}

#[tauri::command]
pub(crate) async fn open_external_url(url: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || open_external_url_blocking(url))
        .await
        .map_err(|error| format!("Открытие внешней ссылки было прервано: {error}"))?
}

pub(crate) fn ensure_admin_launch_blocking(app: AppHandle) -> Result<bool, StateStorageError> {
    crate::elevation::relaunch(&app).map_err(|failure| StateStorageError::new(
        failure.code, "Повышение прав не подтверждено. Настройки не сбрасывались; автоматический повтор не выполняется.", true))
}

#[tauri::command]
pub(crate) async fn ensure_admin_launch(app: AppHandle) -> Result<bool, String> {
    #[cfg(all(not(debug_assertions), target_os = "windows"))]
    {
        if !is_process_elevated()? {
            begin_state_handoff(&app, HandoffAction::Elevate).map_err(|error| error.message)?;
        }
    }
    let _ = app;
    Ok(false)
}

#[tauri::command]
pub(crate) async fn set_launch_on_startup(
    enabled: bool,
    app: AppHandle,
) -> Result<bool, crate::autostart::AutostartError> {
    tauri::async_runtime::spawn_blocking(move || crate::autostart::configure(enabled, app))
        .await
        .map_err(|_| crate::autostart::task_failed())?
}
#[tauri::command]
pub(crate) async fn proxy_status() -> Result<ProxyStatus, String> {
    tauri::async_runtime::spawn_blocking(current_proxy_snapshot)
        .await
        .map_err(|error| format!("Проверка Windows proxy была прервана: {error}"))?
}

#[tauri::command]
pub(crate) async fn set_system_proxy(
    enabled: bool,
    expected_config_path: Option<String>,
    app: AppHandle,
) -> Result<ProxyStatus, NativeFailure> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        set_system_proxy_blocking(enabled, expected_config_path, app)
    })
    .await
    .map_err(|_| NativeFailure::task_failed())?;
    result.map_err(|e: String| NativeFailure::from_error(&e, RuntimeCommand::Proxy))
}

pub(crate) fn set_system_proxy_blocking(
    enabled: bool,
    expected_config_path: Option<String>,
    app: AppHandle,
) -> Result<ProxyStatus, String> {
    let state = app.state::<AppState>();
    let mut _operation_guard =
        begin_open_runtime_operation(&state, Duration::from_secs(6), "runtime-operation")?;
    if let Some(expected) = expected_config_path.as_deref() {
        let runtime = state
            .runtime
            .lock()
            .map_err(|_| "Runtime state повреждён")?;
        require_runtime_config_identity(
            runtime.as_ref().map(|runtime| runtime.config_path.as_str()),
            expected,
        )?;
    }

    if enabled {
        let mut slot = state
            .runtime
            .lock()
            .map_err(|_| "PROBE_RUNTIME_UNAVAILABLE")?;
        let runtime = slot.as_mut().ok_or("PROBE_RUNTIME_UNAVAILABLE")?;
        // A live process alone does not prove the owned HTTP/SOCKS/API
        // listeners survived since connect. Reject before writing WinINet.
        if !owned_runtime_ports_ready(&mut runtime.child)? {
            return Err(
                "CORE_PORT_TIMEOUT: cannot enable proxy before owned listener readiness".into(),
            );
        }
    }
    _operation_guard.check()?;

    let status = if enabled {
        enable_owned_windows_proxy(&app)?
    } else {
        restore_saved_proxy_state(&app, &state, "manual_proxy_toggle")?.unwrap_or_else(|| {
            current_proxy_snapshot().unwrap_or_else(|_| ProxyStatus {
                enabled: false,
                server: None,
                bypass: None,
                method: "unknown".into(),
                scope: "current-user".into(),
                checked_at: unix_now_string(),
                auto_config_url: None,
                auto_detect: false,
            })
        })
    };

    let _ = append_runtime_event(
        &app,
        &format!(
            "Windows system proxy {}; ownership journal сохраняет исходные PAC/bypass/autodetect.",
            if enabled {
                "включён"
            } else {
                "восстановлен/отключён"
            }
        ),
    );
    refresh_tray_menu(&app);
    _operation_guard.commit();
    Ok(status)
}

#[tauri::command]
pub(crate) async fn repair_runtime_environment(
    app: AppHandle,
    plan_id: String,
) -> Result<RuntimeStatus, crate::repair_plan::RepairError> {
    let result =
        tauri::async_runtime::spawn_blocking(move || crate::repair_plan::execute(app, plan_id))
            .await
            .map_err(|_| crate::repair_plan::public_error("REPAIR_EXECUTION_UNCONFIRMED"))?;
    result.map_err(|e| crate::repair_plan::public_error(&e))
}

#[tauri::command]
pub(crate) async fn connectivity_probe(app: AppHandle) -> Result<ConnectivityProbe, String> {
    tauri::async_runtime::spawn_blocking(move || connectivity_probe_blocking(app))
        .await
        .map_err(|error| format!("Проверка маршрута была прервана: {error}"))?
}

fn probe_runtime_identity(app: &AppHandle) -> Result<(u32, u64), String> {
    let snapshot = read_runtime_status(app, app.state::<AppState>());
    match (
        snapshot.tunnel_active,
        snapshot.xray_pid,
        snapshot.operation,
    ) {
        (true, Some(pid), None) => Ok((pid, snapshot.runtime_revision)),
        _ => Err(
            "PROBE_RUNTIME_UNAVAILABLE: no stable owned runtime; no VPN egress was tested".into(),
        ),
    }
}

pub(crate) fn connectivity_probe_blocking(app: AppHandle) -> Result<ConnectivityProbe, String> {
    let identity = probe_runtime_identity(&app)?;
    #[cfg(windows)]
    if !crate::diagnostic_facts::runtime_ports_ready(identity.0)? {
        return Err(
            "CORE_PORT_TIMEOUT: owned listeners are not ready; no VPN egress was tested".into(),
        );
    }
    let checked_at = unix_now_string();
    let http_port_open = tcp_port_open("127.0.0.1", HTTP_PORT, 1200);
    let socks_port_open = tcp_port_open("127.0.0.1", SOCKS_PORT, 1200);

    if !http_port_open {
        if probe_runtime_identity(&app)? != identity {
            return Err("PROBE_RUNTIME_CHANGED: runtime changed during listener observation; result discarded".into());
        }
        return Ok(ConnectivityProbe {
            kind: "xray-http",
            success: false,
            checked_at,
            http_port_open,
            socks_port_open,
            public_ip: None,
            latency_ms: None,
            packet_loss_pct: None,
            message: format!(
                "HTTP inbound 127.0.0.1:{HTTP_PORT} не отвечает. Сначала запустите runtime."
            ),
        });
    }

    let client = build_http_client(
        Some(&format!("http://127.0.0.1:{HTTP_PORT}")),
        Duration::from_secs(8),
    )?;

    let started = Instant::now();
    let public_ip = fetch_public_ip(&client).ok();
    if probe_runtime_identity(&app)? != identity {
        return Err(
            "PROBE_RUNTIME_CHANGED: runtime changed during the HTTP probe; result discarded".into(),
        );
    }
    #[cfg(windows)]
    if !crate::diagnostic_facts::runtime_ports_ready(identity.0)? {
        return Err("PROBE_RUNTIME_CHANGED: owned listeners changed during the HTTP probe; result discarded".into());
    }
    let success = public_ip.is_some();

    Ok(ConnectivityProbe {
        kind: "xray-http",
        success,
        checked_at,
        http_port_open,
        socks_port_open,
        public_ip,
        latency_ms: success.then(|| started.elapsed().as_millis()),
        packet_loss_pct: None,
        message: if success { "HTTP egress through the owned local Xray responded; this is not a TUN, UDP or DNS leak test." } else { "Owned HTTP/SOCKS listener observations are separate: HTTPS egress through Xray failed. Check the selected server; TUN/UDP/DNS were not tested." }.into(),
    })
}

pub(crate) fn server_ping_blocking(
    host: String,
    port: u16,
    _app: Option<AppHandle>,
) -> Result<ConnectivityProbe, String> {
    let normalized_host = normalize_socket_host(&host);
    if normalized_host.is_empty() || port == 0 {
        return Err("PING_INVALID_ENDPOINT".into());
    }
    let mut addresses = resolve_socket_addresses(&normalized_host, port)?;
    addresses.sort_by_key(|address| !address.is_ipv4());
    addresses.dedup();
    addresses.truncate(16);
    let mut count = 0u8;
    let mut total = 0u128;
    let mut path = None;
    let mut failure = String::new();
    for _ in 0..3 {
        let deadline = Instant::now() + Duration::from_millis(850);
        let mut best: Option<ProbePath> = None;
        for address in &addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match direct_tcp_probe(*address, remaining.min(Duration::from_millis(350))) {
                Ok(measured) => {
                    if best
                        .as_ref()
                        .map_or(true, |old| measured.elapsed_micros < old.elapsed_micros)
                    {
                        best = Some(measured);
                    }
                }
                Err(error) => failure = error,
            }
        }
        if let Some(measured) = best {
            count += 1;
            total += measured.elapsed_micros;
            path = Some(measured);
        }
    }
    let message = if let Some(path) = path {
        format!("direct TCP; interface={}; source={}; destination={}; successful={count}/3; failures={}; meanMicros={}; packetLoss=unmeasured",path.interface_index,path.source_ip,path.destination_ip,3-count,total/u128::from(count))
    } else {
        format!("direct TCP unavailable; successful=0/3; failures=3; reason={failure}; packetLoss=unmeasured")
    };
    Ok(ConnectivityProbe {
        kind: "server-direct",
        success: count > 0,
        checked_at: unix_now_string(),
        http_port_open: false,
        socks_port_open: false,
        public_ip: None,
        latency_ms: (count > 0).then(|| (total / u128::from(count)).div_ceil(1000)),
        packet_loss_pct: None,
        message,
    })
}

static PING_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct PingPermit;
impl PingPermit {
    fn acquire() -> Result<Self, String> {
        PING_IN_FLIGHT
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |count| (count < 4).then_some(count + 1),
            )
            .map(|_| Self)
            .map_err(|_| "PING_BUSY: native ping budget exhausted".into())
    }
}
impl Drop for PingPermit {
    fn drop(&mut self) {
        PING_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[tauri::command]
pub(crate) async fn server_ping(
    host: String,
    port: u16,
    app: AppHandle,
) -> Result<ConnectivityProbe, String> {
    let permit = PingPermit::acquire()?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        server_ping_blocking(host, port, Some(app))
    })
    .await
    .map_err(|error| format!("Проверка пинга была прервана: {error}"))?
}

fn query_client_stats(integrity: &LaunchIntegrity) -> Result<(u64, u64), String> {
    let mut command = Command::new(integrity.core.as_path());
    command.args([
        "api",
        "statsquery",
        &format!("--server=127.0.0.1:{XRAY_API_PORT}"),
        "-pattern",
        "inbound>>>",
    ]);
    let raw = run_command_with_timeout(
        command,
        Duration::from_millis(1400),
        "xray readonly statsquery",
    )?;
    parse_client_inbound_stats(&raw)
}

#[tauri::command]
pub(crate) async fn traffic_session_start(app: AppHandle) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<AppState>()
            .traffic
            .lock()
            .map_err(|_| "TRAFFIC_LOCK")?
            .start_session()
    })
    .await
    .map_err(|_| "TRAFFIC_SESSION_INTERRUPTED".to_string())?
}

#[tauri::command]
pub(crate) async fn traffic_snapshot(
    app: AppHandle,
    session_id: u64,
) -> Result<TrafficSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || traffic_snapshot_blocking(app, session_id))
        .await
        .map_err(|error| format!("Traffic task interrupted: {error}"))?
}

pub(crate) fn traffic_snapshot_blocking(
    app: AppHandle,
    session_id: u64,
) -> Result<TrafficSnapshot, String> {
    let state = app.state::<AppState>();
    // Serialize bounded queries without blocking runtime/operation ownership locks.
    let mut totals = state.traffic.try_lock().map_err(|_| "TRAFFIC_BUSY")?;
    let (runtime_id, mode, integrity) = {
        let mut runtime = state.runtime.lock().map_err(|_| "TRAFFIC_RUNTIME_LOCK")?;
        let item = runtime.as_mut().ok_or("TRAFFIC_NO_RUNTIME")?;
        if !matches!(item.child.try_wait(), Ok(None)) {
            return Err("TRAFFIC_RUNTIME_EXITED".into());
        }
        (
            traffic_runtime_id(item),
            item.network_mode.clone(),
            item.child.integrity_lease(),
        )
    };
    let measured = if mode == "tun" {
        tun_counters(TUN_INTERFACE_NAME)
    } else {
        integrity
            .ok_or("TRAFFIC_NO_INTEGRITY".into())
            .and_then(|lease| query_client_stats(&lease))
            .map(|(received, sent)| (runtime_id.clone(), received, sent))
    };
    let mut runtime = state.runtime.lock().map_err(|_| "TRAFFIC_RUNTIME_LOCK")?;
    if runtime
        .as_ref()
        .map_or(true, |item| traffic_runtime_id(item) != runtime_id)
    {
        return Err("TRAFFIC_STALE_RUNTIME".into());
    }
    if !matches!(
        runtime.as_mut().expect("checked runtime").child.try_wait(),
        Ok(None)
    ) {
        return Err("TRAFFIC_RUNTIME_EXITED".into());
    }
    let source = if mode == "tun" {
        "windows-tun-adapter"
    } else {
        "xray-stats"
    };
    match measured {
        Ok((key, received, sent)) => {
            let (received, sent) =
                totals.record(session_id, format!("{source}:{key}"), received, sent)?;
            Ok(TrafficSnapshot {
                baseline_changed: totals.baseline_changed,
                received_bytes: received,
                sent_bytes: sent,
                checked_at: unix_now_string(),
                source: source.into(),
                runtime_id,
                session_id,
                unavailable_reason: None,
            })
        }
        Err(reason) => Ok(TrafficSnapshot {
            baseline_changed: true,
            received_bytes: 0,
            sent_bytes: 0,
            checked_at: unix_now_string(),
            source: "unavailable".into(),
            runtime_id,
            session_id,
            unavailable_reason: Some(reason),
        }),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn parse_wmic_process_list(raw: &str) -> Vec<RunningAppInfo> {
    raw.lines()
        .skip(1)
        .filter_map(|line| {
            let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.len() < 4 {
                return None;
            }
            let pid = parts.last()?.parse::<u32>().ok()?;
            let name = parts.get(parts.len().saturating_sub(2))?.trim().to_string();
            let path = parts[1..parts.len().saturating_sub(2)]
                .join(",")
                .trim()
                .to_string();
            if name.is_empty() || !name.to_lowercase().ends_with(".exe") {
                return None;
            }
            Some(RunningAppInfo {
                pid,
                name,
                path: if path.is_empty() { None } else { Some(path) },
                title: None,
            })
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
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                let _ = chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                values.push(current.trim().to_string());
                current.clear();
            }
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
            if name.is_empty() || !name.to_lowercase().ends_with(".exe") {
                return None;
            }
            Some(RunningAppInfo {
                pid,
                name,
                path: None,
                title: None,
            })
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
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
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

            Some(RunningAppInfo {
                pid,
                name,
                path,
                title,
            })
        })
        .collect()
}

#[cfg(target_os = "windows")]
pub(crate) fn prepare_running_app_inventory(
    apps: Vec<RunningAppInfo>,
    limit: usize,
) -> Result<Vec<RunningAppInfo>, String> {
    let mut seen = std::collections::HashSet::<String>::new();
    let mut unique = apps
        .into_iter()
        .filter(|app| !app.name.trim().is_empty())
        .filter(|app| {
            let identity = app
                .path
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .map(|value| value.trim().replace('\\', "/").to_lowercase())
                .unwrap_or_else(|| app.name.to_lowercase());
            // Keep process instances for the renderer's canonical executable
            // grouping/counts; inaccessible paths cannot become broad exe rules.
            let key = format!("{}:{identity}", app.pid);
            seen.insert(key)
        })
        .collect::<Vec<_>>();

    unique.sort_by(|left, right| {
        let left_has_path = left
            .path
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        let right_has_path = right
            .path
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        let left_has_title = left
            .title
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        let right_has_title = right
            .title
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(false);

        right_has_title
            .cmp(&left_has_title)
            .then_with(|| right_has_path.cmp(&left_has_path))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.pid.cmp(&right.pid))
    });

    if unique.len() > limit {
        return Err("APP_INVENTORY_LIMIT: application list exceeds the bounded inventory; no partial list returned".into());
    }
    Ok(unique)
}

#[cfg(target_os = "windows")]
pub(crate) fn list_running_apps_blocking() -> Result<Vec<RunningAppInfo>, String> {
    match crate::process_inventory::native_running_apps() {
        Ok(apps) => return Ok(apps),
        Err(error) if error.starts_with("APP_INVENTORY_LIMIT") => return Err(error),
        Err(_) => {}
    }
    list_running_apps_fallback()
}

#[cfg(target_os = "windows")]
pub(crate) fn list_running_apps_fallback() -> Result<Vec<RunningAppInfo>, String> {
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

    let mut powershell = Command::new(system_program("powershell")?);
    powershell.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        powershell_script,
    ]);
    if let Ok(raw) = run_command_with_timeout(
        powershell,
        Duration::from_secs(7),
        "powershell user process list",
    ) {
        let apps = parse_powershell_process_list(&raw);
        if !apps.is_empty() {
            return prepare_running_app_inventory(apps, 4096);
        }
    }

    let mut wmic = Command::new(system_program("wmic")?);
    wmic.args([
        "process",
        "where",
        "ExecutablePath is not null",
        "get",
        "ProcessId,Name,ExecutablePath",
        "/FORMAT:CSV",
    ]);
    let raw = run_command_with_timeout(wmic, Duration::from_secs(5), "wmic process list");

    let apps = match raw {
        Ok(value) if value.contains("ExecutablePath") => parse_wmic_process_list(&value),
        _ => {
            let mut tasklist = Command::new(system_program("tasklist")?);
            tasklist.args(["/FO", "CSV", "/NH"]);
            let fallback = run_command_with_timeout(
                tasklist,
                Duration::from_secs(4),
                "tasklist process list",
            )?;
            parse_tasklist_process_list(&fallback)
        }
    };

    prepare_running_app_inventory(apps, 4096)
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
        return (
            format!("Файл Xray повреждён: {error}"),
            Some(core_path_string),
        );
    }

    let integrity = match prepare_core_launch(&core_path, None) {
        Ok(value) => value,
        Err(error) => return (format!("Core integrity: {error}"), Some(core_path_string)),
    };
    let core_path = &integrity.core;
    let mut command = Command::new(core_path);
    command.arg("version");
    command.stdin(Stdio::null());
    hide_child_console(&mut command);

    match run_command_with_timeout(command, Duration::from_secs(4), "xray version") {
        Ok(raw_output) => {
            let first_line = raw_output
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or("Версия не определена")
                .to_string();
            (first_line, Some(core_path_string))
        }
        Err(error) => {
            let friendly = if error.contains("os error 193")
                || error.contains("%1 is not a valid Win32 application")
            {
                "Ошибка запуска Xray: файл не запускается как Windows x64-приложение (os error 193). Запустите START_VKarmani.bat — он проверит и восстановит core.".to_string()
            } else {
                format!("Не удалось запустить Xray-core: {error}")
            };
            (friendly, Some(core_path_string))
        }
    }
}
#[cfg(target_os = "windows")]
pub(crate) fn read_windows_registry_value(key: &str, value_name: &str) -> Option<String> {
    let mut command = Command::new(system_program("reg").ok()?);
    command.args(["query", key, "/v", value_name]);
    run_command_with_timeout(
        command,
        Duration::from_secs(4),
        &format!("reg query {value_name}"),
    )
    .ok()
    .and_then(|raw| parse_reg_value(&raw, value_name))
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

#[cfg(target_os = "windows")]
pub(crate) fn parse_reg_value(raw: &str, value_name: &str) -> Option<String> {
    raw.lines()
        .map(str::trim)
        .find(|line| line.split_whitespace().next() == Some(value_name))
        .and_then(|line| {
            for kind in ["REG_DWORD", "REG_SZ", "REG_EXPAND_SZ"] {
                if let Some(index) = line.find(kind) {
                    return Some(line[index + kind.len()..].trim().to_string());
                }
            }
            None
        })
}

#[cfg(target_os = "windows")]
fn parse_windows_registry_dword(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u32>().ok()
}

#[cfg(target_os = "windows")]
fn normalize_windows_product_name(
    product_name: &str,
    edition_id: Option<&str>,
    build_number: Option<u32>,
) -> String {
    let product = product_name.trim();
    let edition = edition_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "professional" => "Pro".to_string(),
            "enterprise" => "Enterprise".to_string(),
            "education" => "Education".to_string(),
            "core" => "Home".to_string(),
            other => other.to_string(),
        });

    // На Windows 11 реестр часто продолжает отдавать ProductName = "Windows 10 ..."
    // ради совместимости. Определяем поколение по build >= 22000 и не показываем
    // пользователю неверный Windows 10.
    if build_number.unwrap_or_default() >= 22000 {
        if product.to_ascii_lowercase().contains("windows 11") {
            return product.to_string();
        }

        if let Some(edition) = edition {
            return format!("Windows 11 {edition}");
        }

        return product.replacen("Windows 10", "Windows 11", 1);
    }

    if product.is_empty() {
        edition
            .map(|value| format!("Windows {value}"))
            .unwrap_or_else(|| "Windows".to_string())
    } else {
        product.to_string()
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_device_info() -> (String, String, String, String, String, String) {
    let current_version_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let hwid = read_windows_registry_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        .unwrap_or_else(|| "—".to_string());
    let product_name_raw = read_windows_registry_value(current_version_key, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let edition_id = read_windows_registry_value(current_version_key, "EditionID");
    let display_version = read_windows_registry_value(current_version_key, "DisplayVersion")
        .or_else(|| read_windows_registry_value(current_version_key, "ReleaseId"))
        .unwrap_or_else(|| "—".to_string());
    let build_base = read_windows_registry_value(current_version_key, "CurrentBuildNumber")
        .or_else(|| read_windows_registry_value(current_version_key, "CurrentBuild"))
        .unwrap_or_else(|| "—".to_string());
    let build_number = build_base.parse::<u32>().ok();
    let ubr = read_windows_registry_value(current_version_key, "UBR")
        .and_then(|value| parse_windows_registry_dword(&value));
    let build = match (build_base.as_str(), ubr) {
        ("—", _) => "—".to_string(),
        (base, Some(ubr)) => format!("{base}.{ubr}"),
        (base, None) => base.to_string(),
    };
    let product_name =
        normalize_windows_product_name(&product_name_raw, edition_id.as_deref(), build_number);
    let architecture = std::env::var("PROCESSOR_ARCHITECTURE")
        .or_else(|_| std::env::var("PROCESSOR_ARCHITEW6432"))
        .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    let device_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "—".to_string());

    (
        hwid,
        product_name,
        display_version,
        build,
        architecture,
        device_name,
    )
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

fn native_app_info_blocking(app: AppHandle) -> NativeAppInfo {
    let (xray_version, core_path) = read_xray_version(&app);
    let (_, os_name, os_version, os_build, os_architecture, device_name) = windows_device_info();

    NativeAppInfo {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        xray_version,
        hwid: current_remnawave_hwid(),
        os_name,
        os_version,
        os_build,
        os_architecture,
        device_name,
        core_path,
    }
}

#[tauri::command]
pub(crate) async fn native_app_info(app: AppHandle) -> Result<NativeAppInfo, String> {
    tauri::async_runtime::spawn_blocking(move || native_app_info_blocking(app))
        .await
        .map_err(|error| format!("Получение информации о приложении было прервано: {error}"))
}

#[cfg(target_os = "windows")]
fn pick_executable_path_blocking() -> Result<Option<String>, String> {
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

    let mut command = Command::new(system_program("powershell")?);
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

#[cfg(target_os = "windows")]
#[tauri::command]
pub(crate) async fn pick_executable_path() -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(pick_executable_path_blocking)
        .await
        .map_err(|error| format!("Выбор приложения был прерван: {error}"))?
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
pub(crate) async fn pick_executable_path() -> Result<Option<String>, String> {
    Ok(None)
}
#[tauri::command]
pub(crate) fn restart_application(app: AppHandle) -> Result<(), String> {
    begin_state_handoff(&app, HandoffAction::Restart)
        .map(|_| ())
        .map_err(|error| error.message)
}

fn read_runtime_log_blocking(app: AppHandle, lines: Option<usize>) -> Result<Vec<String>, String> {
    tail_runtime_log(&app, lines.unwrap_or(20).clamp(1, 200))
}

#[tauri::command]
pub(crate) async fn read_runtime_log(
    app: AppHandle,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(move || read_runtime_log_blocking(app, lines))
        .await
        .map_err(|error| format!("Чтение runtime-лога было прервано: {error}"))?
}

#[cfg(test)]
mod ping_budget_tests {
    use super::*;
    #[test]
    fn diagnostics_admission_stays_owned_until_native_reader_finishes() {
        let permit = DiagnosticReadPermit::acquire().unwrap();
        assert!(
            std::thread::spawn(|| DiagnosticReadPermit::acquire().is_err())
                .join()
                .unwrap()
        );
        drop(permit);
        assert!(DiagnosticReadPermit::acquire().is_ok());
    }
    #[test]
    fn renderer_cancellation_cannot_accumulate_unbounded_native_ping_tasks() {
        let permits = (0..4)
            .map(|_| PingPermit::acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(PingPermit::acquire().is_err());
        drop(permits);
        let permit = PingPermit::acquire().unwrap();
        drop(permit);
        assert_eq!(PING_IN_FLIGHT.load(std::sync::atomic::Ordering::Acquire), 0);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod application_inventory_tests {
    use super::*;

    fn process(pid: u32, path: Option<&str>) -> RunningAppInfo {
        RunningAppInfo {
            pid,
            name: "app.exe".into(),
            path: path.map(str::to_string),
            title: None,
        }
    }

    #[test]
    fn inventory_retains_process_instances_and_rejects_silent_truncation() {
        let apps = || {
            vec![
                process(1, Some("C:\\App.exe")),
                process(1, Some("c:/app.exe")),
                process(2, Some("C:/App.exe")),
                process(3, None),
                process(4, None),
            ]
        };
        let prepared = prepare_running_app_inventory(apps(), 4).unwrap();
        assert_eq!(prepared.len(), 4);
        assert!(prepared.iter().any(|app| app.pid == 2));
        assert!(prepare_running_app_inventory(apps(), 3)
            .unwrap_err()
            .starts_with("APP_INVENTORY_LIMIT"));
    }
}
