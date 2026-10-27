//! Explicit debug-only owner test build; production admission is unchanged.
use super::*;

pub(crate) const LOCAL_TEST_ID: &str = "com.vkarmani.desktop.localtest";

pub(crate) fn local_test_build() -> bool {
    cfg!(debug_assertions) && option_env!("VKARMANI_LOCAL_TEST") == Some("1")
}

fn configured_root() -> Result<PathBuf, String> {
    let root = PathBuf::from(option_env!("VKARMANI_LOCAL_TEST_DATA").unwrap_or_default());
    if !root.is_absolute()
        || root.file_name().and_then(|v| v.to_str()) != Some("data")
        || root
            .parent()
            .and_then(Path::file_name)
            .and_then(|v| v.to_str())
            != Some(".vkarmani-local-test")
        || root
            .components()
            .any(|v| matches!(v, std::path::Component::ParentDir))
    {
        return Err("LOCAL_TEST_DATA_ISOLATION_REQUIRED".into());
    }
    Ok(root)
}

pub(crate) fn validate_local_test_config(config: &tauri::Config) -> Result<(), String> {
    if option_env!("VKARMANI_LOCAL_TEST") != Some("1") {
        return if config.identifier == LOCAL_TEST_ID {
            Err("LOCAL_TEST_BUILD_MARKER_REQUIRED".into())
        } else {
            Ok(())
        };
    }
    if !local_test_build() || config.identifier != LOCAL_TEST_ID {
        return Err("LOCAL_TEST_REQUIRES_DEBUG_AND_ISOLATED_IDENTIFIER".into());
    }
    let owner = option_env!("VKARMANI_LOCAL_TEST_OWNER").unwrap_or_default();
    if decrypt_access_key(owner).ok().as_deref() != Some("VKarmani local test owner v1") {
        return Err("LOCAL_TEST_REQUIRES_SAME_WINDOWS_USER".into());
    }
    let expected = configured_root()?.join("webview");
    if config.app.windows.len() != 1
        || config.app.windows[0].data_directory.as_deref() != Some(expected.as_path())
    {
        return Err("LOCAL_TEST_WEBVIEW_ISOLATION_REQUIRED".into());
    }
    Ok(())
}

pub(crate) fn application_data_root(app: &AppHandle) -> Result<PathBuf, String> {
    if local_test_build() {
        validate_local_test_config(app.config())?;
        let root = configured_root()?;
        let _pins = ensure_safe_log_directory(&root)?;
        return Ok(root);
    }
    app.path()
        .app_local_data_dir()
        .map_err(|_| "APP_DATA_PATH_UNAVAILABLE".into())
}

pub(crate) fn local_test_metadata(config: &tauri::Config) -> Result<Value, String> {
    validate_local_test_config(config)?;
    if !local_test_build() {
        return Err("NOT_A_LOCAL_TEST_BUILD".into());
    }
    Ok(
        json!({"identifier":config.identifier,"dataRoot":configured_root()?,
        "webviewRoot":configured_root()?.join("webview"),"experimentalTun":true,
        "updatesAllowed":false,"automaticConnectionsAllowed":false}),
    )
}

pub(crate) fn local_config_bytes(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    let encrypted = crate::compat_storage::read_state_file(path, 16 * 1024 * 1024)
        .map_err(|_| "LOCAL_CONFIG_READ_FAILED")?
        .ok_or("LOCAL_CONFIG_MISSING")?;
    let plain = decrypt_access_key(&encrypted).map_err(|_| "LOCAL_CONFIG_DECRYPT_FAILED")?;
    if plain.len() > 2 * 1024 * 1024 {
        return Err("LOCAL_CONFIG_TOO_LARGE".into());
    }
    if sha256_hex_bytes(plain.as_bytes()) != expected {
        return Err("LOCAL_CONFIG_HASH_MISMATCH".into());
    }
    Ok(plain.into_bytes())
}

pub(crate) fn runtime_config_disk_bytes(content: &[u8]) -> Result<Vec<u8>, String> {
    if !local_test_build() {
        return Ok(content.to_vec());
    }
    let value = std::str::from_utf8(content).map_err(|_| "LOCAL_CONFIG_UTF8_REQUIRED")?;
    encrypt_access_key(value).map(String::into_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_build_cannot_become_local_by_identifier_only() {
        let mut config: tauri::Config =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        if !local_test_build() {
            assert!(local_test_metadata(&config).is_err());
            assert!(validate_local_test_config(&config).is_ok());
            config.identifier = LOCAL_TEST_ID.into();
            assert!(validate_local_test_config(&config).is_err());
        }
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn local_encrypted_config_roundtrip_tamper_and_hash_do_not_write_plaintext() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-local-cipher-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("synthetic.dpapi");
        let plain = r#"{"synthetic":"NOT_A_REAL_SUBSCRIPTION"}"#;
        let encrypted = encrypt_access_key(plain).unwrap();
        fs::write(&path, &encrypted).unwrap();
        let hash = sha256_hex_bytes(plain.as_bytes());
        assert_eq!(local_config_bytes(&path, &hash).unwrap(), plain.as_bytes());
        assert!(!fs::read_to_string(&path)
            .unwrap()
            .contains("NOT_A_REAL_SUBSCRIPTION"));
        assert!(local_config_bytes(&path, &"0".repeat(64)).is_err());
        fs::write(&path, "invalid cipher").unwrap();
        assert!(local_config_bytes(&path, &hash).is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
