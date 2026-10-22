use super::*;

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AutostartError {
    pub(crate) code: &'static str,
    category: &'static str,
    retryable: bool,
}
fn failure(code: &'static str) -> AutostartError {
    AutostartError {
        code,
        category: "startup",
        retryable: true,
    }
}
pub(crate) fn task_failed() -> AutostartError {
    failure("AUTOSTART_TASK_FAILED")
}

#[cfg(any(test, all(windows, not(debug_assertions))))]
trait Backend {
    fn read(&mut self) -> Result<Option<String>, AutostartError>;
    fn write(&mut self, value: &str) -> Result<(), AutostartError>;
    fn remove(&mut self) -> Result<(), AutostartError>;
}
#[cfg(any(test, all(windows, not(debug_assertions))))]
fn desired_setting(
    public: &serde_json::Map<String, Value>,
    expected: bool,
    read_only: bool,
    sealed: bool,
) -> Result<(), AutostartError> {
    if read_only || sealed {
        return Err(failure("AUTOSTART_STATE_UNAVAILABLE"));
    }
    let saved = public
        .get("settings")
        .and_then(|s| s.get("launchOnStartup"));
    let desired = match saved {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(failure("AUTOSTART_STATE_UNAVAILABLE")),
    };
    if desired != expected {
        return Err(failure("AUTOSTART_REQUEST_STALE"));
    }
    Ok(())
}
#[cfg(any(test, all(windows, not(debug_assertions))))]
fn apply(backend: &mut impl Backend, target: &str, enabled: bool) -> Result<bool, AutostartError> {
    if target.len() < 3
        || target.len() > 32760
        || target.contains(['\0', '\r', '\n'])
        || !target.starts_with('"')
        || !target.ends_with('"')
        || target[1..target.len() - 1].contains('"')
    {
        return Err(failure("AUTOSTART_TARGET_INVALID"));
    }
    let original = backend.read()?;
    if original.as_deref().is_some_and(|value| value != target) {
        return Err(failure("AUTOSTART_OWNER_CHANGED"));
    }
    if enabled && original.is_none() {
        backend.write(target)?;
    }
    if !enabled && original.is_some() {
        backend.remove()?;
    }
    // No optimistic success after a failed delete, partial apply or unreadable
    // verification. A foreign replacement is never overwritten as rollback.
    let after = backend.read()?;
    if after.as_deref() != enabled.then_some(target) {
        return Err(failure("AUTOSTART_VERIFY_FAILED"));
    }
    Ok(enabled)
}

#[cfg(all(windows, not(debug_assertions)))]
mod windows {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::*,
    };
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    fn key(create: bool) -> Result<Option<Key>, AutostartError> {
        let path = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
        let mut handle = null_mut();
        let code = if create {
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    null_mut(),
                    0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    null(),
                    &mut handle,
                    null_mut(),
                )
            }
        } else {
            unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    KEY_QUERY_VALUE,
                    &mut handle,
                )
            }
        };
        if code == ERROR_FILE_NOT_FOUND && !create {
            return Ok(None);
        }
        if code != ERROR_SUCCESS {
            return Err(failure("AUTOSTART_ACCESS_FAILED"));
        }
        Ok(Some(Key(handle)))
    }
    pub(super) struct Registry;
    impl Backend for Registry {
        fn read(&mut self) -> Result<Option<String>, AutostartError> {
            let Some(key) = key(false)? else {
                return Ok(None);
            };
            let name = wide(STARTUP_REGISTRY_VALUE);
            let mut kind = 0;
            let mut size = 0;
            let first = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    null_mut(),
                    &mut size,
                )
            };
            if first == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if first != ERROR_SUCCESS {
                return Err(failure("AUTOSTART_READ_FAILED"));
            }
            if kind != REG_SZ || !(2..=65536).contains(&size) || size % 2 != 0 {
                return Err(failure("AUTOSTART_VALUE_INVALID"));
            }
            let mut value = vec![0u16; size as usize / 2];
            let code = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    value.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if code != ERROR_SUCCESS {
                return Err(failure("AUTOSTART_READ_FAILED"));
            }
            if kind != REG_SZ || size < 2 || size as usize > value.len() * 2 || size % 2 != 0 {
                return Err(failure("AUTOSTART_VALUE_INVALID"));
            }
            value.truncate(size as usize / 2);
            if value.pop() != Some(0) || value.contains(&0) {
                return Err(failure("AUTOSTART_VALUE_INVALID"));
            }
            String::from_utf16(&value)
                .map(Some)
                .map_err(|_| failure("AUTOSTART_VALUE_INVALID"))
        }
        fn write(&mut self, value: &str) -> Result<(), AutostartError> {
            let key = key(true)?.ok_or_else(|| failure("AUTOSTART_ACCESS_FAILED"))?;
            let value = wide(value);
            let name = wide(STARTUP_REGISTRY_VALUE);
            if unsafe {
                RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    value.as_ptr().cast(),
                    (value.len() * 2) as u32,
                )
            } != ERROR_SUCCESS
            {
                return Err(failure("AUTOSTART_WRITE_FAILED"));
            }
            Ok(())
        }
        fn remove(&mut self) -> Result<(), AutostartError> {
            let path = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
            let mut handle = null_mut();
            let code = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    &mut handle,
                )
            };
            if code == ERROR_FILE_NOT_FOUND {
                return Ok(());
            }
            if code != ERROR_SUCCESS {
                return Err(failure("AUTOSTART_ACCESS_FAILED"));
            }
            let key = Key(handle);
            let name = wide(STARTUP_REGISTRY_VALUE);
            let code = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
            if !matches!(code, ERROR_SUCCESS | ERROR_FILE_NOT_FOUND) {
                return Err(failure("AUTOSTART_DELETE_FAILED"));
            }
            Ok(())
        }
    }
}

pub(crate) fn configure(enabled: bool, app: AppHandle) -> Result<bool, AutostartError> {
    #[cfg(all(windows, not(debug_assertions)))]
    {
        let state = app.state::<AppState>();
        let _storage = state
            .storage_lock
            .lock()
            .map_err(|_| failure("AUTOSTART_STATE_UNAVAILABLE"))?;
        let snapshot = app_durable_store(&app)
            .and_then(|s| s.load())
            .map_err(|_| failure("AUTOSTART_STATE_UNAVAILABLE"))?;
        desired_setting(
            &snapshot.payload.public_state,
            enabled,
            snapshot.read_only,
            state
                .storage_closed
                .load(std::sync::atomic::Ordering::Acquire),
        )?;
        let exe = std::env::current_exe().map_err(|_| failure("AUTOSTART_TARGET_INVALID"))?;
        let target = format!(
            "\"{}\"",
            exe.to_str()
                .ok_or_else(|| failure("AUTOSTART_TARGET_INVALID"))?
        );
        apply(&mut windows::Registry, &target, enabled)
    }
    #[cfg(not(all(windows, not(debug_assertions))))]
    {
        let _ = (enabled, app);
        Err(failure("AUTOSTART_BUILD_UNSUPPORTED"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        value: Option<String>,
        fail: Option<&'static str>,
        writes: usize,
        remove_count: usize,
        drift: bool,
    }
    impl Fake {
        fn new(value: Option<&str>) -> Self {
            Self {
                value: value.map(str::to_string),
                fail: None,
                writes: 0,
                remove_count: 0,
                drift: false,
            }
        }
    }
    impl Backend for Fake {
        fn read(&mut self) -> Result<Option<String>, AutostartError> {
            if self.fail == Some("read") {
                return Err(failure("AUTOSTART_READ_FAILED"));
            }
            Ok(self.value.clone())
        }
        fn write(&mut self, value: &str) -> Result<(), AutostartError> {
            self.writes += 1;
            if self.fail == Some("write") {
                return Err(failure("AUTOSTART_WRITE_FAILED"));
            }
            self.value = Some(if self.drift {
                "foreign".into()
            } else {
                value.into()
            });
            Ok(())
        }
        fn remove(&mut self) -> Result<(), AutostartError> {
            self.remove_count += 1;
            if self.fail == Some("remove") {
                return Err(failure("AUTOSTART_DELETE_FAILED"));
            }
            self.value = None;
            Ok(())
        }
    }
    const TARGET: &str = "\"C:\\Program Files\\VKarmani\\vkarmani-desktop.exe\"";
    #[test]
    fn owned_toggle_and_missing_disable_are_verified_and_idempotent() {
        let mut f = Fake::new(None);
        assert!(!apply(&mut f, TARGET, false).unwrap());
        assert!(apply(&mut f, TARGET, true).unwrap());
        assert!(apply(&mut f, TARGET, true).unwrap());
        assert_eq!(f.writes, 1);
        assert!(!apply(&mut f, TARGET, false).unwrap());
        assert_eq!(f.remove_count, 1);
        assert!(!apply(&mut f, TARGET, false).unwrap());
    }
    #[test]
    fn delete_failure_is_not_reported_as_disabled_or_hidden() {
        let mut f = Fake::new(Some(TARGET));
        f.fail = Some("remove");
        assert_eq!(
            apply(&mut f, TARGET, false).unwrap_err().code,
            "AUTOSTART_DELETE_FAILED"
        );
        assert_eq!(f.value.as_deref(), Some(TARGET));
    }
    #[test]
    fn foreign_value_read_failure_and_write_failure_never_clobber_original() {
        for enabled in [false, true] {
            let mut f = Fake::new(Some("foreign"));
            assert_eq!(
                apply(&mut f, TARGET, enabled).unwrap_err().code,
                "AUTOSTART_OWNER_CHANGED"
            );
            assert_eq!(f.writes + f.remove_count, 0);
        }
        for failure in ["read", "write"] {
            let mut f = Fake::new(None);
            f.fail = Some(failure);
            assert!(apply(&mut f, TARGET, true).is_err());
            assert!(f.value.is_none());
        }
    }
    #[test]
    fn external_drift_is_not_overwritten_as_rollback() {
        let mut f = Fake::new(None);
        f.drift = true;
        assert_eq!(
            apply(&mut f, TARGET, true).unwrap_err().code,
            "AUTOSTART_VERIFY_FAILED"
        );
        assert_eq!(f.value.as_deref(), Some("foreign"));
        assert_eq!(f.writes, 1);
        assert_eq!(f.remove_count, 0);
    }
    #[test]
    fn stale_settings_sealed_recovery_and_malformed_values_block_before_registry() {
        let mut public = serde_json::Map::new();
        assert!(desired_setting(&public, false, false, false).is_ok());
        assert!(desired_setting(&public, true, false, false).is_err());
        public.insert("settings".into(), json!({"launchOnStartup":true}));
        assert!(desired_setting(&public, true, false, false).is_ok());
        assert_eq!(
            desired_setting(&public, false, false, false)
                .unwrap_err()
                .code,
            "AUTOSTART_REQUEST_STALE"
        );
        for (readonly, sealed) in [(true, false), (false, true)] {
            assert!(desired_setting(&public, true, readonly, sealed).is_err());
        }
        public.insert("settings".into(), json!({"launchOnStartup":"yes"}));
        assert!(desired_setting(&public, true, false, false).is_err());
    }
    #[test]
    fn invalid_target_and_error_json_do_not_expose_paths() {
        let mut f = Fake::new(None);
        for target in ["", "unquoted", "\"x\n\""] {
            assert_eq!(
                apply(&mut f, target, true).unwrap_err().code,
                "AUTOSTART_TARGET_INVALID"
            );
        }
        assert_eq!(f.writes, 0);
        assert_eq!(
            serde_json::to_value(failure("AUTOSTART_OWNER_CHANGED")).unwrap(),
            json!({"code":"AUTOSTART_OWNER_CHANGED","category":"startup","retryable":true})
        );
    }
}
