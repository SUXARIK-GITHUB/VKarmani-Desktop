use super::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StateStorageError {
    pub(crate) code: &'static str,
    category: &'static str,
    pub(crate) message: String,
    recoverable: bool,
    suggested_action: &'static str,
    os_error: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) current_generation: Option<Box<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) current_revision: Option<Box<str>>,
}
impl StateStorageError {
    pub(crate) fn new(code: &'static str, message: &str, recoverable: bool) -> Self {
        Self {
            code,
            category: "storage",
            message: message.into(),
            recoverable,
            suggested_action: "retry-storage-or-open-diagnostics",
            os_error: None,
            current_generation: None,
            current_revision: None,
        }
    }
    pub(crate) fn io(error: std::io::Error) -> Self {
        let mut failure = Self::new(
            "STATE_READ_FAILED",
            "Не удалось прочитать состояние. Сохранённые данные оставлены без изменений.",
            true,
        );
        failure.os_error = error.raw_os_error();
        failure
    }
    pub(crate) fn write_io(error: std::io::Error, code: &'static str) -> Self {
        let mut failure = Self::new(
            code,
            "Не удалось сохранить состояние. Предыдущее состояние не удалялось.",
            true,
        );
        failure.os_error = error.raw_os_error();
        failure
    }
}
impl From<String> for StateStorageError {
    fn from(_value: String) -> Self {
        Self::new(
            "STATE_WRITE_FAILED",
            "Не удалось сохранить состояние. Проверьте хранилище в диагностике.",
            true,
        )
    }
}
impl From<&str> for StateStorageError {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

pub(crate) struct ClientStateSnapshot {
    pub(crate) values: serde_json::Map<String, Value>,
    #[cfg(test)]
    plaintext: Option<String>,
    pub(crate) recovered: bool,
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lkg.dpapi");
    PathBuf::from(name)
}

fn parse_document(
    plaintext: &str,
    limit: u64,
) -> Result<serde_json::Map<String, Value>, StateStorageError> {
    if plaintext.len() as u64 > limit {
        return Err(StateStorageError::new(
            "STATE_TOO_LARGE",
            "Сохранённое состояние превышает допустимый размер.",
            false,
        ));
    }
    let value: Value = serde_json::from_str(plaintext).map_err(|_| {
        StateStorageError::new(
            "STATE_CORRUPT",
            "Сохранённое состояние повреждено. Оригинал не изменён.",
            false,
        )
    })?;
    let map = value.as_object().ok_or_else(|| {
        StateStorageError::new(
            "STATE_CORRUPT",
            "Ожидался объект сохранённого состояния. Оригинал не изменён.",
            false,
        )
    })?;
    // This first preservation fix intentionally retains the legacy flat schema.
    // Never reinterpret a future envelope as empty legacy settings or downgrade it.
    if map.contains_key("schemaVersion") || map.contains_key("_vkarmaniState") {
        return Err(StateStorageError::new(
            "STATE_UNSUPPORTED_SCHEMA",
            "Версия сохранённого состояния требует проверки совместимости.",
            false,
        ));
    }
    Ok(map.clone())
}

pub(crate) fn read_client_state_at(
    path: &Path,
    sensitive: bool,
) -> Result<ClientStateSnapshot, StateStorageError> {
    let plain_limit = if sensitive {
        SENSITIVE_CLIENT_STATE_MAX_BYTES
    } else {
        CLIENT_STATE_MAX_BYTES
    };
    let read_limit = if sensitive {
        ENCRYPTED_STATE_MAX_BYTES
    } else {
        plain_limit
    };
    let raw = read_state_file(path, read_limit).map_err(StateStorageError::io)?;
    let primary = raw
        .as_ref()
        .map(|raw| -> Result<_, StateStorageError> {
            let plaintext = if sensitive {
                decrypt_access_key(raw).map_err(|_| {
                    StateStorageError::new(
                        "STATE_CORRUPT",
                        "Защищённое состояние не удалось проверить. Оригинал не изменён.",
                        false,
                    )
                })?
            } else {
                raw.clone()
            };
            Ok((parse_document(&plaintext, plain_limit)?, plaintext))
        })
        .transpose();
    let primary_error = match primary {
        Ok(Some((values, _plaintext))) => {
            return Ok(ClientStateSnapshot {
                values,
                #[cfg(test)]
                plaintext: Some(_plaintext),
                recovered: false,
            })
        }
        Err(error) if error.code == "STATE_CORRUPT" => Some(error),
        Err(error) => return Err(error),
        Ok(None) => None,
    };
    let backup = read_state_file(&backup_path(path), ENCRYPTED_STATE_MAX_BYTES)
        .map_err(StateStorageError::io)?;
    if let Some(ciphertext) = backup {
        let plaintext = decrypt_access_key(&ciphertext).map_err(|_| {
            StateStorageError::new(
                "STATE_BACKUP_CORRUPT",
                "Резервную копию состояния не удалось проверить.",
                false,
            )
        })?;
        let values = parse_document(&plaintext, plain_limit)?;
        return Ok(ClientStateSnapshot {
            values,
            #[cfg(test)]
            plaintext: Some(plaintext),
            recovered: true,
        });
    }
    match primary_error {
        Some(error) => Err(error),
        None => Ok(ClientStateSnapshot {
            values: serde_json::Map::new(),
            #[cfg(test)]
            plaintext: None,
            recovered: false,
        }),
    }
}

#[cfg(test)]
pub(crate) fn update_client_state_at(
    path: &Path,
    sensitive: bool,
    key: &str,
    value: Option<Value>,
) -> Result<(), StateStorageError> {
    let snapshot = read_client_state_at(path, sensitive)?;
    if snapshot.recovered {
        // A valid backup may be displayed read-only. Replacing a corrupt original
        // requires an explicit recovery action, never an incidental autosave.
        return Err(StateStorageError::new("STATE_RECOVERY_REQUIRED", "Загружена резервная копия. Для записи требуется явное восстановление; оригинал сохранён.", false));
    }
    let mut values = snapshot.values;
    let clearing = value.is_none();
    if let Some(value) = value {
        values.insert(key.into(), value);
    } else {
        values.remove(key);
    }
    values.insert("updatedAt".into(), Value::String(unix_now_string()));
    let plaintext = serde_json::to_string(&Value::Object(values)).map_err(|_| {
        StateStorageError::new(
            "STATE_INVALID_VALUE",
            "Состояние не удалось сериализовать.",
            false,
        )
    })?;
    let limit = if sensitive {
        SENSITIVE_CLIENT_STATE_MAX_BYTES
    } else {
        CLIENT_STATE_MAX_BYTES
    };
    if plaintext.len() as u64 > limit {
        return Err(StateStorageError::new(
            "STATE_TOO_LARGE",
            "Новое состояние превышает допустимый размер.",
            false,
        ));
    }
    let payload = if sensitive {
        encrypt_access_key(&plaintext)?
    } else {
        plaintext.clone()
    };
    let backup_plaintext = if clearing {
        Some(plaintext)
    } else {
        snapshot.plaintext
    };
    if let Some(previous) = backup_plaintext {
        // Backup is always DPAPI, including public legacy data that might still
        // contain a profile awaiting migration. No plaintext backup is created.
        let backup = encrypt_access_key(&previous)?;
        atomic_write_state_text(&backup_path(path), &backup)
            .map_err(|error| StateStorageError::write_io(error, "STATE_BACKUP_WRITE_FAILED"))?;
    }
    atomic_write_state_text(path, &payload)
        .map_err(|error| StateStorageError::write_io(error, "STATE_WRITE_FAILED"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-client-state-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        (dir.clone(), dir.join("state.json"))
    }
    fn cleanup(dir: &Path) {
        for file in fs::read_dir(dir).unwrap() {
            fs::remove_file(file.unwrap().path()).unwrap();
        }
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn missing_is_empty_but_empty_invalid_or_future_documents_are_not() {
        let (dir, path) = fixture();
        assert!(read_client_state_at(&path, false)
            .unwrap()
            .values
            .is_empty());
        for invalid in [
            "",
            "null",
            "[]",
            "{",
            r#"{"schemaVersion":999,"payload":{}}"#,
        ] {
            fs::write(&path, invalid).unwrap();
            assert!(read_client_state_at(&path, false).is_err());
            assert!(update_client_state_at(&path, false, "settings", Some(json!({}))).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
        }
        cleanup(&dir);
    }
    #[test]
    #[cfg(windows)]
    fn a_read_sharing_failure_cannot_be_replaced_with_an_incomplete_map() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
        let (dir, path) = fixture();
        let original = r#"{"settings":{"language":"ru"},"splitTunnelEntries":[{"id":"keep"}],"favoriteServerIds":["keep"],"futureField":{"keep":true}}"#;
        fs::write(&path, original).unwrap();
        // The other handle denies reads but permits rename/delete. A writer
        // that unwraps the failed read to {} would successfully destroy keys.
        let blocker = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        let result = update_client_state_at(&path, false, "selectedServerId", Some(json!("new")));
        drop(blocker);
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        cleanup(&dir);
    }
    #[test]
    #[cfg(windows)]
    fn verified_encrypted_backup_restores_read_only_and_preserves_corrupt_primary() {
        let (dir, path) = fixture();
        update_client_state_at(&path, false, "settings", Some(json!({"language":"ru"}))).unwrap();
        update_client_state_at(&path, false, "favoriteServerIds", Some(json!(["one"]))).unwrap();
        let ciphertext = fs::read_to_string(backup_path(&path)).unwrap();
        assert!(!ciphertext.contains("language"));
        fs::write(&path, "corrupt-original").unwrap();
        let snapshot = read_client_state_at(&path, false).unwrap();
        assert!(snapshot.recovered);
        assert_eq!(snapshot.values["settings"]["language"], "ru");
        assert!(update_client_state_at(&path, false, "settings", Some(json!({}))).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "corrupt-original");
        fs::write(backup_path(&path), "invalid-backup").unwrap();
        assert!(read_client_state_at(&path, false).is_err());
        cleanup(&dir);
    }
    #[test]
    #[cfg(windows)]
    fn corrupt_protected_state_is_not_overwritten_and_unknown_legacy_keys_survive() {
        let (dir, path) = fixture();
        fs::write(&path, "damaged-ciphertext").unwrap();
        assert!(update_client_state_at(&path, true, "lastKnownServers", Some(json!([]))).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "damaged-ciphertext");
        fs::write(
            &path,
            encrypt_access_key(r#"{"futureField":{"keep":true}}"#).unwrap(),
        )
        .unwrap();
        update_client_state_at(&path, true, "lastKnownServers", Some(json!([]))).unwrap();
        assert_eq!(
            read_client_state_at(&path, true).unwrap().values["futureField"]["keep"],
            true
        );
        cleanup(&dir);
    }
    #[test]
    #[cfg(windows)]
    fn cleared_protected_profile_cannot_reappear_from_a_backup() {
        let (dir, path) = fixture();
        update_client_state_at(
            &path,
            true,
            "lastKnownServers",
            Some(json!(["synthetic-private-profile"])),
        )
        .unwrap();
        update_client_state_at(&path, true, "lastKnownServers", None).unwrap();
        fs::write(&path, "damaged-after-clear").unwrap();
        let recovered = read_client_state_at(&path, true).unwrap();
        assert!(recovered.recovered);
        assert!(!recovered.values.contains_key("lastKnownServers"));
        cleanup(&dir);
    }
    #[test]
    #[cfg(windows)]
    fn backup_failure_aborts_primary_commit_and_preserves_unknown_fields() {
        let (dir, path) = fixture();
        let original = r#"{"settings":{"language":"en"},"futureField":{"keep":true}}"#;
        fs::write(&path, original).unwrap();
        fs::create_dir(backup_path(&path)).unwrap();
        let failure =
            update_client_state_at(&path, false, "favoriteServerIds", Some(json!(["new"])))
                .unwrap_err();
        assert_eq!(failure.code, "STATE_BACKUP_WRITE_FAILED");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir(backup_path(&path)).unwrap();
        cleanup(&dir);
    }
    #[test]
    #[cfg(windows)]
    fn serialized_concurrent_native_updates_preserve_every_committed_key() {
        let (dir, path) = fixture();
        let lock = std::sync::Mutex::new(());
        std::thread::scope(|scope| {
            for index in 0..16 {
                let (lock, path) = (&lock, &path);
                scope.spawn(move || {
                    let _guard = lock.lock().unwrap(); // Same critical section as AppState.storage_lock.
                    update_client_state_at(
                        path,
                        false,
                        &format!("synthetic-{index}"),
                        Some(json!(index)),
                    )
                    .unwrap();
                });
            }
        });
        let snapshot = read_client_state_at(&path, false).unwrap();
        for index in 0..16 {
            assert_eq!(snapshot.values[&format!("synthetic-{index}")], index);
        }
        cleanup(&dir);
    }
    #[test]
    fn oversize_or_structurally_invalid_input_cannot_destroy_existing_state() {
        let (dir, path) = fixture();
        fs::write(&path, r#"{"futureField":"keep"}"#).unwrap();
        let original = fs::read(&path).unwrap();
        assert_eq!(
            update_client_state_at(
                &path,
                false,
                "settings",
                Some(json!("x".repeat(CLIENT_STATE_MAX_BYTES as usize)))
            )
            .unwrap_err()
            .code,
            "STATE_TOO_LARGE"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::write(&path, [0xff, 0xfe]).unwrap();
        let failure = read_client_state_at(&path, false).err().unwrap();
        assert_eq!(failure.category, "storage");
        let wire = serde_json::to_value(failure).unwrap();
        assert!(wire["code"].as_str().unwrap().starts_with("STATE_"));
        assert!(wire.get("suggestedAction").is_some());
        assert!(update_client_state_at(&path, false, "settings", Some(json!({}))).is_err());
        assert_eq!(fs::read(&path).unwrap(), [0xff, 0xfe]);
        cleanup(&dir);
    }
}
