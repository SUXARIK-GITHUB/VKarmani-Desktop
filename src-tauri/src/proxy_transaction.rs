use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProxySettings {
    pub(crate) flags: u32,
    pub(crate) server: String,
    pub(crate) bypass: String,
    pub(crate) pac: String,
}
impl ProxySettings {
    fn owned_target() -> Self {
        Self {
            flags: 3,
            server: format!("http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT}"),
            bypass: PROXY_BYPASS.into(),
            pac: String::new(),
        }
    }
    fn can_rollback_partial(&self, original: &Self, target: &Self) -> bool {
        (self.flags == original.flags || self.flags == target.flags)
            && (self.server == original.server || self.server == target.server)
            && (self.bypass == original.bypass || self.bypass == target.bypass)
            && (self.pac == original.pac || self.pac == target.pac)
    }
    pub(crate) fn status(&self) -> ProxyStatus {
        ProxyStatus {
            enabled: self.flags & 2 != 0,
            server: (!self.server.is_empty()).then(|| self.server.clone()),
            bypass: (!self.bypass.is_empty()).then(|| self.bypass.clone()),
            method: "wininet-api".into(),
            scope: "current-user".into(),
            checked_at: unix_now_string(),
            auto_config_url: (!self.pac.is_empty()).then(|| self.pac.clone()),
            auto_detect: self.flags & 8 != 0,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProxyJournal {
    version: u8,
    #[serde(default)]
    owner_pid: u32,
    original: ProxySettings,
    target: ProxySettings,
    applied: bool,
}
trait ProxyBackend {
    fn read(&mut self) -> Result<ProxySettings, String>;
    fn write(&mut self, settings: &ProxySettings) -> Result<(), String>;
    fn save(&mut self, journal: &ProxyJournal) -> Result<(), String>;
    fn clear(&mut self) -> Result<(), String>;
}
fn restore_transaction(
    backend: &mut impl ProxyBackend,
    journal: &ProxyJournal,
) -> Result<Option<ProxySettings>, String> {
    ensure_previous_owner_inactive(journal.owner_pid)?;
    let current = backend.read()?;
    if current == journal.original {
        backend.clear()?;
        return Ok(Some(current));
    }
    if current != journal.target
        && (journal.applied || !current.can_rollback_partial(&journal.original, &journal.target))
    {
        return Err("PROXY_OWNERSHIP_CHANGED: Windows proxy изменён другим владельцем. Его настройки сохранены; backup оставлен для проверки.".into());
    }
    backend.save(&ProxyJournal {
        applied: false,
        ..journal.clone()
    })?;
    backend.write(&journal.original)?;
    let restored = backend.read()?;
    if restored != journal.original {
        return Err(
            "PROXY_RESTORE_FAILED: исходные WinINet настройки не подтверждены; backup сохранён."
                .into(),
        );
    }
    backend.clear()?;
    Ok(Some(restored))
}
fn enable_transaction(
    backend: &mut impl ProxyBackend,
    previous: Option<ProxyJournal>,
) -> Result<ProxyJournal, String> {
    let current = backend.read()?;
    if let Some(journal) = previous {
        ensure_previous_owner_inactive(journal.owner_pid)?;
        if journal.version != 2 {
            return Err("Неподдерживаемый proxy journal".into());
        }
        if current == journal.target && journal.applied {
            return Ok(journal);
        }
        restore_transaction(backend, &journal)?;
    }
    let original = backend.read()?;
    let target = ProxySettings::owned_target();
    // A loopback endpoint alone is not proof that this instance owns it.
    if original == target {
        return Err(
            "PROXY_UNKNOWN_OWNER: loopback proxy уже установлен без journal владельца.".into(),
        );
    }
    let mut journal = ProxyJournal {
        version: 2,
        owner_pid: std::process::id(),
        original,
        target,
        applied: false,
    };
    backend.save(&journal)?; // durable recovery information BEFORE any side effect
    let result = backend.write(&journal.target).and_then(|_| {
        if backend.read()? != journal.target {
            return Err("WinINet не подтвердил запрошенный proxy".into());
        }
        journal.applied = true;
        backend.save(&journal)
    });
    if let Err(error) = result {
        let rollback = restore_transaction(
            backend,
            &ProxyJournal {
                applied: false,
                ..journal
            },
        );
        return Err(match rollback {
            Ok(_) => format!("Proxy setup failed; original settings restored: {error}"),
            Err(_) => {
                "PROXY_ROLLBACK_FAILED: backup сохранён, восстановление не подтверждено.".into()
            }
        });
    }
    Ok(journal)
}

#[cfg(target_os = "windows")]
pub(crate) fn read_wininet_settings() -> Result<ProxySettings, String> {
    use windows_sys::Win32::Networking::WinInet::*;
    let mut options = [
        INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_PROXY_SERVER,
        INTERNET_PER_CONN_PROXY_BYPASS,
        INTERNET_PER_CONN_AUTOCONFIG_URL,
    ]
    .map(|dw_option| INTERNET_PER_CONN_OPTIONW {
        dwOption: dw_option,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: null_mut(),
        },
    });
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let mut bytes = std::mem::size_of_val(&list) as u32;
    let ok = unsafe {
        InternetQueryOptionW(
            null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &mut list as *mut _ as *mut _,
            &mut bytes,
        )
    };
    // Query allocates each string with GlobalAlloc, including on a partial
    // query. Free every returned pointer after copying, even on an error.
    let copy = |pointer: *mut u16| -> Result<String, String> {
        if pointer.is_null() {
            return Ok(String::new());
        }
        let result = (|| {
            let mut chars = Vec::new();
            for index in 0..32768 {
                let character = unsafe { *pointer.add(index) };
                if character == 0 {
                    return String::from_utf16(&chars)
                        .map_err(|_| "Некорректный WinINet UTF-16".into());
                }
                chars.push(character);
            }
            Err("WinINet строка превышает лимит".into())
        })();
        unsafe {
            GlobalFree(pointer as *mut _);
        }
        result
    };
    let server = copy(unsafe { options[1].Value.pszValue });
    let bypass = copy(unsafe { options[2].Value.pszValue });
    let pac = copy(unsafe { options[3].Value.pszValue });
    if ok == 0 {
        return Err("Не удалось прочитать WinINet proxy/PAC/autodetect snapshot.".into());
    }
    Ok(ProxySettings {
        flags: unsafe { options[0].Value.dwValue },
        server: server?,
        bypass: bypass?,
        pac: pac?,
    })
}
#[cfg(target_os = "windows")]
fn write_wininet_settings(settings: &ProxySettings) -> Result<(), String> {
    use windows_sys::Win32::Networking::WinInet::*;
    let wide = |text: &str| -> Result<Vec<u16>, String> {
        if text.contains('\0') || text.len() > 65536 {
            return Err("Некорректная WinINet настройка".into());
        }
        Ok(text.encode_utf16().chain(Some(0)).collect())
    };
    let mut server = wide(&settings.server)?;
    let mut bypass = wide(&settings.bypass)?;
    let mut pac = wide(&settings.pac)?;
    let mut options = [
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                dwValue: settings.flags,
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: server.as_mut_ptr(),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: bypass.as_mut_ptr(),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: pac.as_mut_ptr(),
            },
        },
    ];
    let list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    if unsafe {
        InternetSetOptionW(
            null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &list as *const _ as *const _,
            std::mem::size_of_val(&list) as u32,
        )
    } == 0
    {
        return Err("WinINet отклонил изменение proxy/PAC/autodetect.".into());
    }
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        if unsafe { InternetSetOptionW(null(), option, null(), 0) } == 0 {
            return Err("WinINet refresh не подтверждён.".into());
        }
    }
    Ok(())
}
#[cfg(not(target_os = "windows"))]
pub(crate) fn read_wininet_settings() -> Result<ProxySettings, String> {
    Err("Windows WinINet недоступен".into())
}

struct NativeProxyBackend<'a> {
    app: &'a AppHandle,
}
fn journal_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Нет proxy journal каталога".to_string())?
        .join("system-proxy-ownership-v2.dpapi"))
}
fn load_journal(app: &AppHandle) -> Result<Option<ProxyJournal>, String> {
    let path = journal_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    if fs::metadata(&path)
        .map_err(|_| "Не удалось проверить proxy journal".to_string())?
        .len()
        > 256 * 1024
    {
        return Err("Proxy journal превышает лимит".into());
    }
    let payload =
        fs::read_to_string(&path).map_err(|_| "Не удалось прочитать proxy journal".to_string())?;
    let journal: ProxyJournal = serde_json::from_str(&decrypt_access_key(&payload)?)
        .map_err(|_| "Proxy journal повреждён".to_string())?;
    if journal.version != 2 {
        return Err("Неподдерживаемый proxy journal".into());
    }
    ensure_previous_owner_inactive(journal.owner_pid)?;
    if journal.target != ProxySettings::owned_target()
        || [&journal.original, &journal.target].iter().any(|settings| {
            settings.flags > 15
                || [&settings.server, &settings.bypass, &settings.pac]
                    .iter()
                    .any(|text| text.contains('\0') || text.len() > 65536)
        })
    {
        return Err("Proxy journal содержит неверную структуру".into());
    }
    Ok(Some(journal))
}
impl ProxyBackend for NativeProxyBackend<'_> {
    fn read(&mut self) -> Result<ProxySettings, String> {
        read_wininet_settings()
    }
    fn write(&mut self, settings: &ProxySettings) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            write_wininet_settings(settings)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = settings;
            Err("Windows WinINet недоступен".into())
        }
    }
    fn save(&mut self, journal: &ProxyJournal) -> Result<(), String> {
        let plaintext = serde_json::to_string(journal)
            .map_err(|_| "Proxy journal serialization failed".to_string())?;
        if plaintext.len() > 128 * 1024 {
            return Err("Proxy journal превышает лимит".into());
        }
        atomic_write_text(
            &journal_path(self.app)?,
            &encrypt_access_key(&plaintext)?,
            "Proxy journal",
        )
    }
    fn clear(&mut self) -> Result<(), String> {
        let path = journal_path(self.app)?;
        if path.exists() {
            fs::remove_file(path)
                .map_err(|_| "Не удалось удалить завершённый proxy journal".to_string())?;
        }
        Ok(())
    }
}
pub(crate) fn enable_owned_windows_proxy(app: &AppHandle) -> Result<ProxyStatus, String> {
    let mut backend = NativeProxyBackend { app };
    let journal = enable_transaction(&mut backend, load_journal(app)?)?;
    Ok(journal.target.status())
}
pub(crate) fn restore_owned_windows_proxy(app: &AppHandle) -> Result<Option<ProxyStatus>, String> {
    let Some(journal) = load_journal(app)? else {
        return Ok(None);
    };
    restore_transaction(&mut NativeProxyBackend { app }, &journal)
        .map(|value| value.map(|settings| settings.status()))
}
pub(crate) fn windows_proxy_ownership_state(app: &AppHandle) -> String {
    match load_journal(app) {
        Ok(None) => "none",
        Ok(Some(journal)) => match read_wininet_settings() {
            Ok(current) if current == journal.target => {
                if journal.applied {
                    "owned"
                } else {
                    "prepared"
                }
            }
            Ok(current) if current == journal.original => "restored-pending-journal",
            Ok(_) => "changed",
            Err(_) => "unavailable",
        },
        Err(_) => "corrupt",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        current: ProxySettings,
        journal: Option<ProxyJournal>,
        writes: usize,
        fail_write: Option<usize>,
        fail_save: bool,
    }
    impl ProxyBackend for Fake {
        fn read(&mut self) -> Result<ProxySettings, String> {
            Ok(self.current.clone())
        }
        fn write(&mut self, settings: &ProxySettings) -> Result<(), String> {
            self.writes += 1;
            if self.fail_write == Some(self.writes) {
                self.current.server = settings.server.clone();
                return Err("injected partial write".into());
            }
            self.current = settings.clone();
            Ok(())
        }
        fn save(&mut self, journal: &ProxyJournal) -> Result<(), String> {
            if self.fail_save {
                return Err("injected disk failure".into());
            }
            self.journal = Some(journal.clone());
            Ok(())
        }
        fn clear(&mut self) -> Result<(), String> {
            self.journal = None;
            Ok(())
        }
    }
    fn backend() -> Fake {
        Fake {
            current: ProxySettings {
                flags: 13,
                server: "user.example:8080".into(),
                bypass: "intranet;<local>".into(),
                pac: "https://pac.example/config.pac".into(),
            },
            journal: None,
            writes: 0,
            fail_write: None,
            fail_save: false,
        }
    }
    #[test]
    fn restores_original_proxy_pac_bypass_autodetect_and_is_idempotent() {
        let mut backend = backend();
        let original = backend.current.clone();
        let journal = enable_transaction(&mut backend, None).unwrap();
        assert_eq!(backend.current.flags, 3);
        assert!(backend.current.pac.is_empty());
        enable_transaction(&mut backend, Some(journal.clone())).unwrap();
        assert_eq!(backend.writes, 1);
        restore_transaction(&mut backend, &journal).unwrap();
        assert_eq!(backend.current, original);
        assert!(backend.journal.is_none());
    }
    #[test]
    fn setup_disk_and_partial_write_failures_preserve_or_restore_original() {
        let mut fake = backend();
        let original = fake.current.clone();
        fake.fail_save = true;
        assert!(enable_transaction(&mut fake, None).is_err());
        assert_eq!(fake.writes, 0);
        assert_eq!(fake.current, original);
        fake.fail_save = false;
        fake.fail_write = Some(1);
        assert!(enable_transaction(&mut fake, None).is_err());
        assert_eq!(fake.current, original);
        assert!(fake.journal.is_none());
    }
    #[test]
    fn changed_user_owner_is_never_overwritten_and_failed_restore_retains_journal() {
        let mut fake = backend();
        let journal = enable_transaction(&mut fake, None).unwrap();
        fake.current.server = "another-owner:8080".into();
        let foreign = fake.current.clone();
        assert!(restore_transaction(&mut fake, &journal)
            .unwrap_err()
            .starts_with("PROXY_OWNERSHIP_CHANGED"));
        assert_eq!(fake.current, foreign);
        assert!(fake.journal.is_some());
        fake.current = journal.target.clone();
        fake.fail_write = Some(fake.writes + 1);
        assert!(restore_transaction(&mut fake, &journal).is_err());
        assert!(fake.journal.is_some());
        let retry_journal = fake.journal.clone().unwrap();
        fake.fail_write = None;
        restore_transaction(&mut fake, &retry_journal).unwrap();
        assert!(fake.journal.is_none());
    }
    #[test]
    fn recovers_prepared_crash_record_and_rejects_unknown_loopback_owner() {
        let mut fake = backend();
        let original = fake.current.clone();
        let journal = ProxyJournal {
            version: 2,
            owner_pid: std::process::id(),
            original: original.clone(),
            target: ProxySettings::owned_target(),
            applied: false,
        };
        fake.current = journal.target.clone();
        fake.journal = Some(journal.clone());
        restore_transaction(&mut fake, &journal).unwrap();
        assert_eq!(fake.current, original);
        fake.current = ProxySettings::owned_target();
        assert!(enable_transaction(&mut fake, None)
            .unwrap_err()
            .starts_with("PROXY_UNKNOWN_OWNER"));
    }
    #[test]
    fn repeated_100_proxy_transactions_preserve_pac_and_leave_no_owned_journal() {
        let mut fake = backend();
        let original = fake.current.clone();
        for _ in 0..100 {
            let journal = enable_transaction(&mut fake, None).unwrap();
            restore_transaction(&mut fake, &journal).unwrap();
        }
        assert_eq!(fake.current, original);
        assert!(fake.journal.is_none());
        assert_eq!(fake.writes, 200);
        // Injected backend stress, not100 live Windows proxy writes.
    }
    #[test]
    fn rollback_guard_restores_on_drop_and_preserves_committed_runtime() {
        let mut fake = backend();
        let original = fake.current.clone();
        let journal = enable_transaction(&mut fake, None).unwrap();
        {
            let _rollback = FailedConnectRollback::new(|| {
                restore_transaction(&mut fake, &journal).unwrap();
            });
        }
        assert_eq!(fake.current, original);
        assert!(fake.journal.is_none());
        let mut fake = backend();
        let journal = enable_transaction(&mut fake, None).unwrap();
        // Preflight/unconfirmed-stop never arms this guard.
        assert_eq!(fake.current, journal.target);
        {
            let mut rollback = FailedConnectRollback::new(|| {
                restore_transaction(&mut fake, &journal).unwrap();
            });
            rollback.commit();
        }
        assert_eq!(fake.current, journal.target);
        assert!(fake.journal.is_some());
        restore_transaction(&mut fake, &journal).unwrap();
    }
    #[test]
    fn rollback_guard_retains_journal_on_foreign_change_or_partial_restore_failure() {
        for foreign_change in [true, false] {
            let mut fake = backend();
            let journal = enable_transaction(&mut fake, None).unwrap();
            if foreign_change {
                fake.current.server = "foreign-owner:8080".into();
            } else {
                fake.fail_write = Some(fake.writes + 1);
            }
            let before = fake.current.clone();
            let mut failure = None;
            {
                let _rollback = FailedConnectRollback::new(|| {
                    failure = restore_transaction(&mut fake, &journal).err();
                });
            }
            assert!(failure.is_some());
            assert!(fake.journal.is_some());
            if foreign_change {
                assert!(failure.unwrap().starts_with("PROXY_OWNERSHIP_CHANGED"));
                assert_eq!(fake.current, before);
            } else {
                assert!(fake.journal.as_ref().is_some_and(|saved| !saved.applied));
                fake.fail_write = None;
                let saved = fake.journal.clone().unwrap();
                restore_transaction(&mut fake, &saved).unwrap();
                assert!(fake.journal.is_none());
                assert_eq!(fake.current, journal.original);
            }
        }
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn native_wininet_snapshot_query_is_read_only_and_bounded() {
        let settings = read_wininet_settings();
        assert!(settings.is_ok(), "WinINet read-only query failed");
        let settings = settings.unwrap();
        assert!(settings.flags <= 15);
        assert!(
            settings.server.len() <= 131072
                && settings.bypass.len() <= 131072
                && settings.pac.len() <= 131072
        );
        // No settings mutation, serialization or secret-value output.
    }
}
