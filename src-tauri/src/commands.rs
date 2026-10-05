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

pub(crate) fn secure_access_key_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("access-key.dpapi"))
}

pub(crate) fn client_state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("client-state-v1.json"))
}

pub(crate) fn sensitive_client_state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("sensitive-client-state-v1.dpapi"))
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

pub(crate) fn is_allowed_sensitive_client_state_key(key: &str) -> bool {
    matches!(key, "lastKnownServers")
}

pub(crate) fn read_client_state_map(
    app: &AppHandle,
) -> Result<serde_json::Map<String, Value>, String> {
    let path = client_state_path(app)?;
    if !path.exists() {
        return Ok(serde_json::Map::new());
    }

    let metadata = fs::metadata(&path)
        .map_err(|error| format!("Не удалось проверить сохранённые настройки клиента: {error}"))?;
    if metadata.len() > CLIENT_STATE_MAX_BYTES {
        return Err(
            "Файл сохранённых настроек клиента слишком большой и не будет загружен.".to_string(),
        );
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
                .unwrap_or_else(|| {
                    format!("client-state-v1.json.corrupt-{}", unix_timestamp_seconds())
                });
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

fn save_client_state_value_blocking(
    key: String,
    value: String,
    app: AppHandle,
) -> Result<(), String> {
    let storage_state = app.state::<AppState>();
    let _storage_guard = storage_state
        .storage_lock
        .lock()
        .map_err(|_| "Не удалось заблокировать хранилище состояния.".to_string())?;

    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    if value.len() as u64 > CLIENT_STATE_MAX_BYTES {
        return Err("Настройки клиента слишком большие.".into());
    }
    let parsed_value: Value = serde_json::from_str(&value).map_err(|error| {
        format!("Не удалось сохранить настройки клиента: некорректный JSON: {error}")
    })?;

    let mut map = read_client_state_map(&app).unwrap_or_default();
    map.insert(normalized_key.to_string(), parsed_value);
    map.insert("updatedAt".to_string(), Value::String(unix_now_string()));

    let payload = serde_json::to_string_pretty(&Value::Object(map)).map_err(|error| {
        format!("Не удалось подготовить настройки клиента к сохранению: {error}")
    })?;

    if payload.len() as u64 > CLIENT_STATE_MAX_BYTES {
        return Err("Настройки клиента слишком большие.".into());
    }
    let path = client_state_path(&app)?;
    atomic_write_text(&path, &payload, "Не удалось сохранить настройки клиента")
}

fn load_client_state_value_blocking(key: String, app: AppHandle) -> Result<Option<String>, String> {
    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    let map = read_client_state_map(&app)?;
    Ok(map
        .get(normalized_key)
        .and_then(|value| serde_json::to_string(value).ok()))
}

fn clear_client_state_value_blocking(key: String, app: AppHandle) -> Result<(), String> {
    let storage_state = app.state::<AppState>();
    let _storage_guard = storage_state
        .storage_lock
        .lock()
        .map_err(|_| "Не удалось заблокировать хранилище состояния.".to_string())?;

    let normalized_key = key.trim();
    if !is_allowed_client_state_key(normalized_key) {
        return Err("Недопустимый ключ клиентского состояния.".into());
    }

    let mut map = read_client_state_map(&app).unwrap_or_default();
    map.remove(normalized_key);
    map.insert("updatedAt".to_string(), Value::String(unix_now_string()));

    let payload = serde_json::to_string_pretty(&Value::Object(map)).map_err(|error| {
        format!("Не удалось подготовить настройки клиента к сохранению: {error}")
    })?;

    if payload.len() as u64 > CLIENT_STATE_MAX_BYTES {
        return Err("Настройки клиента слишком большие.".into());
    }
    let path = client_state_path(&app)?;
    atomic_write_text(&path, &payload, "Не удалось сохранить настройки клиента")
}

#[tauri::command]
pub(crate) async fn save_client_state_value(
    key: String,
    value: String,
    app: AppHandle,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || save_client_state_value_blocking(key, value, app))
        .await
        .map_err(|error| format!("Сохранение настроек клиента было прервано: {error}"))?
}

#[tauri::command]
pub(crate) async fn load_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || load_client_state_value_blocking(key, app))
        .await
        .map_err(|error| format!("Загрузка настроек клиента была прервана: {error}"))?
}

#[tauri::command]
pub(crate) async fn clear_client_state_value(key: String, app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || clear_client_state_value_blocking(key, app))
        .await
        .map_err(|error| format!("Очистка настроек клиента была прервана: {error}"))?
}

fn read_sensitive_client_state_map(
    app: &AppHandle,
) -> Result<serde_json::Map<String, Value>, String> {
    let path = sensitive_client_state_path(app)?;
    if !path.exists() {
        return Ok(serde_json::Map::new());
    }

    let metadata = fs::metadata(&path)
        .map_err(|error| format!("Не удалось проверить защищённый кэш клиента: {error}"))?;
    if metadata.len() > ENCRYPTED_STATE_MAX_BYTES {
        return Err(
            "Файл защищённого кэша клиента слишком большой и не будет загружен.".to_string(),
        );
    }

    let encrypted = fs::read_to_string(&path)
        .map_err(|error| format!("Не удалось прочитать защищённый кэш клиента: {error}"))?;
    if encrypted.trim().is_empty() {
        return Ok(serde_json::Map::new());
    }

    let decrypted = decrypt_access_key(encrypted.trim()).map_err(|error| {
        let backup_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|name| format!("{name}.corrupt-{}", unix_timestamp_seconds()))
            .unwrap_or_else(|| {
                format!(
                    "sensitive-client-state-v1.dpapi.corrupt-{}",
                    unix_timestamp_seconds()
                )
            });
        let backup_path = path.with_file_name(backup_name);
        let _ = fs::copy(&path, &backup_path);
        let _ = append_interface_event(
            app,
            &format!(
                "Защищённый кэш клиента повреждён и не будет загружен: {error}. Backup: {}",
                backup_path.display()
            ),
        );
        format!("Не удалось расшифровать защищённый кэш клиента: {error}")
    })?;

    if decrypted.len() as u64 > SENSITIVE_CLIENT_STATE_MAX_BYTES {
        return Err(
            "Расшифрованный защищённый кэш клиента слишком большой и не будет загружен."
                .to_string(),
        );
    }

    if decrypted.trim().is_empty() {
        return Ok(serde_json::Map::new());
    }

    let value: Value = serde_json::from_str(&decrypted).map_err(|error| {
        let backup_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|name| format!("{name}.invalid-json-{}", unix_timestamp_seconds()))
            .unwrap_or_else(|| format!("sensitive-client-state-v1.dpapi.invalid-json-{}", unix_timestamp_seconds()));
        let backup_path = path.with_file_name(backup_name);
        let _ = fs::copy(&path, &backup_path);
        let _ = append_interface_event(
            app,
            &format!(
                "Защищённый кэш клиента содержит некорректный JSON и не будет загружен: {error}. Backup: {}",
                backup_path.display()
            ),
        );
        format!("Защищённый кэш клиента содержит некорректный JSON: {error}")
    })?;

    Ok(value.as_object().cloned().unwrap_or_default())
}

fn save_sensitive_client_state_value_blocking(
    key: String,
    value: String,
    app: AppHandle,
) -> Result<(), String> {
    let storage_state = app.state::<AppState>();
    let _storage_guard = storage_state
        .storage_lock
        .lock()
        .map_err(|_| "Не удалось заблокировать хранилище состояния.".to_string())?;

    let normalized_key = key.trim();
    if !is_allowed_sensitive_client_state_key(normalized_key) {
        return Err("Недопустимый ключ защищённого клиентского состояния.".into());
    }

    if value.len() as u64 > SENSITIVE_CLIENT_STATE_MAX_BYTES {
        return Err(
            "Защищённое клиентское состояние слишком большое и не будет сохранено.".to_string(),
        );
    }

    let parsed_value: Value = serde_json::from_str(&value).map_err(|error| {
        format!("Не удалось сохранить защищённый кэш клиента: некорректный JSON: {error}")
    })?;

    let mut map = read_sensitive_client_state_map(&app).unwrap_or_default();
    map.insert(normalized_key.to_string(), parsed_value);
    map.insert("updatedAt".to_string(), Value::String(unix_now_string()));

    let payload = serde_json::to_string(&Value::Object(map)).map_err(|error| {
        format!("Не удалось подготовить защищённый кэш клиента к сохранению: {error}")
    })?;
    if payload.len() as u64 > SENSITIVE_CLIENT_STATE_MAX_BYTES {
        return Err("Защищённый кэш клиента слишком большой и не будет сохранён.".to_string());
    }

    let encrypted = encrypt_access_key(&payload)
        .map_err(|error| format!("Не удалось зашифровать защищённый кэш клиента: {error}"))?;
    let path = sensitive_client_state_path(&app)?;
    atomic_write_text(
        &path,
        &encrypted,
        "Не удалось сохранить защищённый кэш клиента",
    )
}

fn load_sensitive_client_state_value_blocking(
    key: String,
    app: AppHandle,
) -> Result<Option<String>, String> {
    let normalized_key = key.trim();
    if !is_allowed_sensitive_client_state_key(normalized_key) {
        return Err("Недопустимый ключ защищённого клиентского состояния.".into());
    }

    let map = read_sensitive_client_state_map(&app)?;
    Ok(map
        .get(normalized_key)
        .and_then(|value| serde_json::to_string(value).ok()))
}

fn clear_sensitive_client_state_value_blocking(key: String, app: AppHandle) -> Result<(), String> {
    let storage_state = app.state::<AppState>();
    let _storage_guard = storage_state
        .storage_lock
        .lock()
        .map_err(|_| "Не удалось заблокировать хранилище состояния.".to_string())?;

    let normalized_key = key.trim();
    if !is_allowed_sensitive_client_state_key(normalized_key) {
        return Err("Недопустимый ключ защищённого клиентского состояния.".into());
    }

    let mut map = read_sensitive_client_state_map(&app).unwrap_or_default();
    map.remove(normalized_key);
    map.insert("updatedAt".to_string(), Value::String(unix_now_string()));

    let payload = serde_json::to_string(&Value::Object(map)).map_err(|error| {
        format!("Не удалось подготовить защищённый кэш клиента к очистке: {error}")
    })?;
    let encrypted = encrypt_access_key(&payload).map_err(|error| {
        format!("Не удалось зашифровать защищённый кэш клиента после очистки: {error}")
    })?;
    let path = sensitive_client_state_path(&app)?;
    atomic_write_text(
        &path,
        &encrypted,
        "Не удалось очистить защищённый кэш клиента",
    )
}

#[tauri::command]
pub(crate) async fn save_sensitive_client_state_value(
    key: String,
    value: String,
    app: AppHandle,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        save_sensitive_client_state_value_blocking(key, value, app)
    })
    .await
    .map_err(|error| format!("Сохранение защищённого кэша клиента было прервано: {error}"))?
}

#[tauri::command]
pub(crate) async fn load_sensitive_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        load_sensitive_client_state_value_blocking(key, app)
    })
    .await
    .map_err(|error| format!("Загрузка защищённого кэша клиента была прервана: {error}"))?
}

#[tauri::command]
pub(crate) async fn clear_sensitive_client_state_value(
    key: String,
    app: AppHandle,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        clear_sensitive_client_state_value_blocking(key, app)
    })
    .await
    .map_err(|error| format!("Очистка защищённого кэша клиента была прервана: {error}"))?
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

fn save_access_key_secure_blocking(value: String, app: AppHandle) -> Result<(), String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return clear_access_key_secure_blocking(app);
    }
    let storage_state = app.state::<AppState>();
    let _storage_guard = storage_state
        .storage_lock
        .lock()
        .map_err(|_| "Не удалось заблокировать хранилище состояния.".to_string())?;
    let normalized = normalize_access_key_for_native(normalized)?;
    let encrypted = encrypt_access_key(&normalized)?;
    let path = secure_access_key_path(&app)?;
    atomic_write_text(
        &path,
        &encrypted,
        "Не удалось сохранить ключ доступа в защищённое хранилище",
    )
}

pub(crate) fn load_access_key_secure_blocking(app: AppHandle) -> Result<Option<String>, String> {
    let path = secure_access_key_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("Не удалось проверить защищённый ключ доступа: {error}"))?;
    if metadata.len() > 64 * 1024 {
        return Err(
            "Файл защищённого ключа выглядит слишком большим и не будет загружен.".to_string(),
        );
    }

    let encrypted = fs::read_to_string(path)
        .map_err(|error| format!("Не удалось прочитать защищённый ключ доступа: {error}"))?;
    let value = decrypt_access_key(encrypted.trim())?;
    Ok(Some(normalize_access_key_for_native(&value)?))
}

fn clear_access_key_secure_blocking(app: AppHandle) -> Result<(), String> {
    let storage_state = app.state::<AppState>();
    let _storage_guard = storage_state
        .storage_lock
        .lock()
        .map_err(|_| "Не удалось заблокировать хранилище состояния.".to_string())?;

    let path = secure_access_key_path(&app)?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("Не удалось удалить сохранённый ключ доступа: {error}"))?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn save_access_key_secure(value: String, app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || save_access_key_secure_blocking(value, app))
        .await
        .map_err(|error| format!("Сохранение ключа доступа было прервано: {error}"))?
}

#[tauri::command]
pub(crate) async fn load_access_key_secure(app: AppHandle) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || load_access_key_secure_blocking(app))
        .await
        .map_err(|error| format!("Загрузка ключа доступа была прервана: {error}"))?
}

#[tauri::command]
pub(crate) async fn clear_access_key_secure(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || clear_access_key_secure_blocking(app))
        .await
        .map_err(|error| format!("Очистка ключа доступа была прервана: {error}"))?
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
        return Err("Сначала войдите по ключу VKarmani, затем запускайте подключение.".into());
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
                "Xray запущен, но локальные порты не стали готовы за {} мс ({ports_state}). {details}",
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
) -> Result<RuntimeStatus, String> {
    let (runtime_template, verified_fingerprint) = verified_template_identity(
        &runtime_template,
        &canonical_template_json,
        server_fingerprint.as_deref(),
    )?;
    let requested_generation = app
        .state::<AppState>()
        .operation_generation
        .load(std::sync::atomic::Ordering::Acquire);
    tauri::async_runtime::spawn_blocking(move || {
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
    .map_err(|error| format!("Подключение Xray было прервано: {error}"))?
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
        .map_err(|error| format!("Xray-core не принял runtime-конфиг. Подключение остановлено до запуска процесса: {error}"))
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
    let mut _operation_guard = acquire_operation_lock(&state, Duration::from_secs(8), "connect")?;
    if state
        .operation_generation
        .load(std::sync::atomic::Ordering::Acquire)
        != requested_generation
    {
        return Err("OPERATION_CANCELLED: подключение отменено до изменения runtime.".into());
    }

    let core_path = resolve_core_path(&app).ok_or_else(|| core_not_found_message(&app))?;
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

    let policy_mode = tun_routing_mode.as_deref().unwrap_or("selected");
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
    if normalized_network_mode == "tun" && !is_process_elevated()? {
        return Err("TUN режим требует запуска VKarmani с правами администратора, иначе Windows не даст создать маршруты. Откройте настройки клиента и включите запуск от администратора или перезапустите приложение вручную от имени администратора.".into());
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
    .map_err(|error| format!("CONNECT_PREFLIGHT: {error}"))?;

    #[cfg(target_os = "windows")]
    if let Some(route) = physical_route.as_ref() {
        bind_tun_outbounds(&mut config, &route.interface_alias)
            .map_err(|error| format!("CONNECT_PREFLIGHT: {error}"))?;
    }

    let config_text = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Не удалось сериализовать config: {error}"))?;
    let config_hash = sha256_hex_bytes(config_text.as_bytes());
    _operation_guard.check()?;
    _operation_guard.stage("stopping")?;
    stop_managed_or_starting_runtime(
        &app,
        &state,
        !reconnect_requested || normalized_network_mode == "tun",
        "connect_preflight",
    )?;
    let config_written = std::cell::Cell::new(false);
    let mut failed_connect = FailedConnectRollback::new(|| {
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
            format!("{first_release_error}; повторная очистка Xray не освободила порты: {second_release_error}")
        })?;
    }
    if reconnect_requested {
        let _ = append_runtime_event(&app, "Старый Xray остановлен, локальные порты освобождены, запускаем выбранный сервер без наложения процессов.");
    }
    ensure_runtime_ports_available()?;

    validate_or_create_log(&runtime_trace_path).map_err(|error| format!("CONNECT_LOG: {error}"))?;
    _operation_guard.stage("validating")?;
    write_new_runtime_config(&config_path, config_text.as_bytes())
        .map_err(|error| format!("Не удалось записать config: {error}"))?;
    config_written.set(true);

    validate_xray_config_with_core(&core_path, &config_path, &config_hash).inspect_err(
        |error| {
            let _ = append_runtime_event(&app, error);
            remove_startup_runtime_config(&app, &config_path, "config_validation_failed");
        },
    )?;
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
        configure_tun_routes(&app, TUN_INTERFACE_NAME, &outbound_ips).map_err(|error| {
            clear_starting_runtime(&state, child_pid);
            let _ = cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &outbound_ips);
            let _ = restore_saved_proxy_state(&app, &state, "tun_routes_failed");
            let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
            remove_startup_runtime_config(&app, &config_path, "tun_routes_failed");
            format!("Не удалось подготовить Windows-маршруты для TUN режима: {error}")
        })?;
        let _ = append_runtime_event(
            &app,
            "Owned IPv4/IPv6 split routes applied; unselected traffic DIRECT.",
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
        clear_starting_runtime(&state, child_pid);
        let code = status.code();
        if let Ok(mut exit_guard) = state.last_exit_code.lock() {
            *exit_guard = code;
        }
        let _ = cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &outbound_ips);
        let _ = restore_saved_proxy_state(&app, &state, "connect_final_check_failed");
        remove_startup_runtime_config(&app, &config_path, "xray_stopped_before_ready_final_check");
        return Err(format!(
            "Xray остановился до завершения подключения. Exit code: {:?}. Подключение не было помечено активным.",
            code
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
    let status = build_runtime_status(&app, app.state::<AppState>());
    drop(_operation_guard);
    Ok(status)
}

#[tauri::command]
pub(crate) async fn rollback_failed_connect(
    expected_config_path: String,
    app: AppHandle,
) -> Result<RuntimeStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
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
        Ok(build_runtime_status(&app, app.state::<AppState>()))
    })
    .await
    .map_err(|_| "Откат подключения был прерван".to_string())?
}

#[tauri::command]
pub(crate) async fn request_disconnect(app: AppHandle) -> Result<RuntimeStatus, String> {
    app.state::<AppState>()
        .stop_requested
        .store(true, std::sync::atomic::Ordering::Release);
    app.state::<AppState>()
        .operation_generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    tauri::async_runtime::spawn_blocking(move || request_disconnect_blocking(app))
        .await
        .map_err(|error| format!("Отключение Xray было прервано: {error}"))?
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

fn ensure_admin_launch_blocking(app: AppHandle) -> Result<bool, String> {
    #[cfg(all(not(debug_assertions), target_os = "windows"))]
    {
        if is_process_elevated()? {
            return Ok(false);
        }

        let executable = std::env::current_exe()
            .map_err(|error| format!("Не удалось определить путь к приложению: {error}"))?;

        let args = std::env::args()
            .skip(1)
            .map(|item| ps_quote(&item))
            .collect::<Vec<_>>();
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
pub(crate) async fn ensure_admin_launch(app: AppHandle) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || ensure_admin_launch_blocking(app))
        .await
        .map_err(|error| format!("Проверка запуска от администратора была прервана: {error}"))?
}

fn set_launch_on_startup_blocking(enabled: bool, app: AppHandle) -> Result<bool, String> {
    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    {
        let executable = std::env::current_exe()
            .map_err(|error| format!("Не удалось определить путь к приложению: {error}"))?;
        let executable = format!("\"{}\"", executable.to_string_lossy());
        let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

        if enabled {
            let mut command = Command::new(system_program("reg")?);
            command.args([
                "add",
                run_key,
                "/v",
                STARTUP_REGISTRY_VALUE,
                "/t",
                "REG_SZ",
                "/d",
                &executable,
                "/f",
            ]);
            run_command_with_timeout(command, Duration::from_secs(4), "enable startup")?;
        } else {
            let mut command = Command::new(system_program("reg")?);
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
pub(crate) async fn set_launch_on_startup(enabled: bool, app: AppHandle) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || set_launch_on_startup_blocking(enabled, app))
        .await
        .map_err(|error| format!("Изменение автозапуска было прервано: {error}"))?
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
) -> Result<ProxyStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        set_system_proxy_blocking(enabled, expected_config_path, app)
    })
    .await
    .map_err(|error| format!("Изменение Windows proxy было прервано: {error}"))?
}

pub(crate) fn set_system_proxy_blocking(
    enabled: bool,
    expected_config_path: Option<String>,
    app: AppHandle,
) -> Result<ProxyStatus, String> {
    let state = app.state::<AppState>();
    let mut _operation_guard =
        acquire_operation_lock(&state, Duration::from_secs(6), "runtime-operation")?;
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

    let is_connected = state
        .runtime
        .lock()
        .map(|mut runtime| {
            runtime
                .as_mut()
                .is_some_and(|runtime| matches!(runtime.child.try_wait(), Ok(None)))
        })
        .unwrap_or(false);
    if enabled && !is_connected {
        return Err("Сначала запустите runtime, затем включайте системный proxy.".into());
    }

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
pub(crate) async fn repair_runtime_environment(app: AppHandle) -> Result<RuntimeStatus, String> {
    tauri::async_runtime::spawn_blocking(move || repair_runtime_environment_blocking(app))
        .await
        .map_err(|error| format!("Восстановление runtime окружения было прервано: {error}"))?
}

pub(crate) fn repair_runtime_environment_blocking(app: AppHandle) -> Result<RuntimeStatus, String> {
    let state = app.state::<AppState>();
    let mut _operation_guard =
        acquire_operation_lock(&state, Duration::from_secs(6), "runtime-operation")?;

    let is_connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    if is_connected {
        return Err(
            "Сначала отключите VPN, затем запускайте восстановление runtime окружения.".into(),
        );
    }

    restore_saved_proxy_state(&app, &state, "manual_runtime_repair")?;
    cleanup_tun_routes_for_app(&app, TUN_INTERFACE_NAME, &[])?;
    let _ = cleanup_runtime_config_files(&app);
    let _ = append_runtime_event(
        &app,
        "Выполнено ручное восстановление runtime окружения: proxy/routes/runtime-config cleanup.",
    );
    refresh_tray_menu(&app);
    _operation_guard.commit();
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
    let public_ip = fetch_public_ip(&client)?;

    Ok(ConnectivityProbe {
        success: true,
        checked_at,
        http_port_open,
        socks_port_open,
        public_ip: Some(public_ip),
        latency_ms: Some(started.elapsed().as_millis()),
        packet_loss_pct: None,
        message: "Маршрут через локальный Xray runtime отвечает.".into(),
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
pub(crate) fn dedupe_and_limit_running_apps(
    apps: Vec<RunningAppInfo>,
    limit: usize,
) -> Vec<RunningAppInfo> {
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
            return Ok(dedupe_and_limit_running_apps(apps, 200));
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
    cleanup_application(&app, "restart_application");
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("Не удалось определить путь приложения: {error}"))?;
    let mut command = Command::new(current_exe);
    hide_child_console(&mut command);
    command
        .spawn()
        .map_err(|error| format!("Не удалось перезапустить приложение: {error}"))?;
    app.exit(0);
    Ok(())
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
