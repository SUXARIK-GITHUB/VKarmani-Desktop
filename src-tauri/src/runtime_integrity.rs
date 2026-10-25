use super::*;

const COMPILED_CORE_MANIFEST: &str =
    include_str!("../../resources/core/windows/core-manifest.json");
pub(crate) fn compiled_artifact_identity(name: &str) -> Result<(u64, String), String> {
    let manifest: Value =
        serde_json::from_str(COMPILED_CORE_MANIFEST.trim_start_matches('\u{feff}'))
            .map_err(|_| "COMPILED_MANIFEST_INVALID")?;
    let entry = manifest["files"]
        .as_array()
        .ok_or("COMPILED_MANIFEST_INVALID")?
        .iter()
        .find(|v| v["file"].as_str() == Some(name))
        .ok_or("ARTIFACT_NOT_PINNED")?;
    let size = entry["size"].as_u64().ok_or("ARTIFACT_SIZE_INVALID")?;
    let hash = entry["sha256"]
        .as_str()
        .ok_or("ARTIFACT_HASH_INVALID")?
        .to_string();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("ARTIFACT_HASH_INVALID".into());
    }
    Ok((size, hash))
}
pub(crate) struct LaunchIntegrity {
    pub(crate) core: PathBuf,
    pub(crate) config: Option<PathBuf>,
    _files: Vec<File>,
    staged_config: bool,
}
impl Drop for LaunchIntegrity {
    fn drop(&mut self) {
        self._files.clear();
        if self.staged_config {
            if let Some(path) = &self.config {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    #[test]
    fn junction_config_parent_is_rejected_before_execution() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("vkarmani-junction-{}", std::process::id()));
        let target = dir.join("target");
        let link = dir.join("link");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("config.json"), b"{}").unwrap();
        let cmd = system_program("reg")
            .unwrap()
            .parent()
            .unwrap()
            .join("cmd.exe");
        let mut command = Command::new(cmd);
        command
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target);
        assert!(
            run_command_with_timeout(command, Duration::from_secs(3), "synthetic junction").is_ok()
        );
        let core =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../resources/core/windows/xray.exe");
        let error = prepare_core_launch(
            &core,
            Some((&link.join("config.json"), &sha256_hex_bytes(b"{}"))),
        )
        .err()
        .unwrap();
        assert!(error.contains("REPARSE"));
        fs::remove_dir(&link).unwrap(); // junction itself only, never target recursion
        fs::remove_file(target.join("config.json")).unwrap();
        fs::remove_dir(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use windows_sys::Win32::{
        Foundation::*, Security::Authorization::*, Security::*, Storage::FileSystem::*,
        System::Com::CoTaskMemFree, UI::Shell::*,
    };
    fn wide(path: &Path) -> Result<Vec<u16>, String> {
        use std::os::windows::ffi::OsStrExt;
        let v = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if v.contains(&0) {
            return Err("PATH_NUL".into());
        }
        Ok(v.into_iter().chain(Some(0)).collect())
    }
    fn lock(path: &Path, directory: bool) -> Result<File, String> {
        let metadata = fs::symlink_metadata(path).map_err(|_| "PROVENANCE_PATH_UNAVAILABLE")?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.is_dir() != directory
        {
            return Err("PROVENANCE_REPARSE_OR_TYPE".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)
            .map_err(|_| "PROVENANCE_LOCK_FAILED")?;
        if file
            .metadata()
            .map_err(|_| "PROVENANCE_METADATA")?
            .file_attributes()
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err("PROVENANCE_REPARSE".into());
        }
        Ok(file)
    }
    pub(super) fn lock_ancestors(path: &Path) -> Result<Vec<File>, String> {
        let mut ancestors = path.ancestors().skip(1).collect::<Vec<_>>();
        ancestors.reverse();
        if !path.is_absolute() {
            return Err("PROVENANCE_ABSOLUTE_PATH_REQUIRED".into());
        }
        ancestors.into_iter().map(|p| lock(p, true)).collect()
    }
    fn verified_file(path: &Path, size: Option<u64>, hash: &str) -> Result<File, String> {
        let mut file = lock(path, false)?;
        let actual_size = file.metadata().map_err(|_| "PROVENANCE_METADATA")?.len();
        if size.is_some_and(|size| size != actual_size) || actual_size > 80 * 1024 * 1024 {
            return Err("PROVENANCE_SIZE_MISMATCH".into());
        }
        let mut digest = Sha256::new();
        let mut bytes = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut bytes).map_err(|_| "PROVENANCE_READ")?;
            if n == 0 {
                break;
            }
            digest.update(&bytes[..n]);
        }
        let actual = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if actual != hash {
            return Err("PROVENANCE_HASH_MISMATCH".into());
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| "PROVENANCE_SEEK")?;
        Ok(file)
    }
    pub(super) fn read_config(path: &Path, hash: &str) -> Result<Value, String> {
        let _parents = lock_ancestors(path)?;
        let mut file = verified_file(path, None, hash)?;
        if file.metadata().map_err(|_| "CONFIG_METADATA")?.len() > 2 * 1024 * 1024 {
            return Err("CONFIG_TOO_LARGE".into());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| "CONFIG_READ")?;
        serde_json::from_slice(&bytes).map_err(|_| "CONFIG_JSON_INVALID".into())
    }
    #[test]
    fn recovery_config_reader_verifies_hash_json_limit_and_preserves_input() {
        let dir =
            std::env::temp_dir().join(format!("vkarmani-recovery-reader-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("config.json");
        let bytes = br#"{"outbounds":[],"synthetic":true}"#;
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            read_config(&path, &sha256_hex_bytes(bytes)).unwrap()["synthetic"],
            json!(true)
        );
        assert!(read_config(&path, &"0".repeat(64))
            .unwrap_err()
            .contains("HASH_MISMATCH"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::write(&path, b"not json").unwrap();
        assert!(read_config(&path, &sha256_hex_bytes(b"not json"))
            .unwrap_err()
            .contains("JSON_INVALID"));
        let large = vec![b' '; 2 * 1024 * 1024 + 1];
        fs::write(&path, &large).unwrap();
        assert!(read_config(&path, &sha256_hex_bytes(&large))
            .unwrap_err()
            .contains("TOO_LARGE"));
        assert_eq!(fs::metadata(&path).unwrap().len(), large.len() as u64);
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    static STAGE_ARTIFACT_LOCK: Mutex<()> = Mutex::new(());
    fn stage_verified_artifact(
        source: &mut impl Read,
        destination: &Path,
        size: u64,
        hash: &str,
    ) -> Result<File, String> {
        // Concurrent version/config/runtime checks share this protected package.
        // Publish complete bytes and acquire the read-only integrity lease before
        // another caller can inspect an in-progress copy. Retained leases still
        // prohibit mutation/deletion; existing bytes are always verified.
        let _stage = STAGE_ARTIFACT_LOCK
            .lock()
            .map_err(|_| "STAGE_ARTIFACT_LOCK_FAILED")?;
        if !destination.exists() {
            let mut target = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|_| "STAGE_ARTIFACT_CREATE")?;
            let write_result = std::io::copy(source, &mut target)
                .map_err(|_| "STAGE_ARTIFACT_COPY")
                .and_then(|_| target.sync_all().map_err(|_| "STAGE_ARTIFACT_FLUSH"));
            drop(target);
            if let Err(error) = write_result {
                let _ = fs::remove_file(destination);
                return Err(error.into());
            }
        }
        verified_file(destination, Some(size), hash)
    }
    #[test]
    fn concurrent_stage_waits_for_complete_verified_artifact() {
        use std::sync::mpsc;
        struct PausedSource {
            data: std::io::Cursor<Vec<u8>>,
            ready: Option<mpsc::Sender<()>>,
            release: mpsc::Receiver<()>,
        }
        impl Read for PausedSource {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if let Some(ready) = self.ready.take() {
                    ready.send(()).unwrap();
                    self.release.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                self.data.read(buffer)
            }
        }
        let dir = std::env::temp_dir().join(format!("vkarmani-stage-race-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("artifact.dat");
        let data = b"verified complete artifact".to_vec();
        let hash = sha256_hex_bytes(&data);
        let size = data.len() as u64;
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_path = path.clone();
        let first_hash = hash.clone();
        let first_data = data.clone();
        let first = std::thread::spawn(move || {
            stage_verified_artifact(
                &mut PausedSource {
                    data: std::io::Cursor::new(first_data),
                    ready: Some(ready_tx),
                    release: release_rx,
                },
                &first_path,
                size,
                &first_hash,
            )
        });
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (result_tx, result_rx) = mpsc::channel();
        let second_path = path.clone();
        let second_hash = hash.clone();
        let second = std::thread::spawn(move || {
            let result = stage_verified_artifact(
                &mut std::io::Cursor::new(data),
                &second_path,
                size,
                &second_hash,
            );
            result_tx
                .send(result.as_ref().map(|_| ()).map_err(Clone::clone))
                .unwrap();
            result
        });
        let early_result = result_rx.recv_timeout(Duration::from_millis(100));
        release_tx.send(()).unwrap();
        let first_pin = first.join().unwrap().unwrap();
        let second_result = second.join().unwrap();
        assert!(
            matches!(early_result, Err(mpsc::RecvTimeoutError::Timeout)),
            "reader observed unfinished publication: {early_result:?}"
        );
        let second_pin = second_result.unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());
        assert!(stage_verified_artifact(
            &mut std::io::Cursor::new(b"replacement"),
            &path,
            size,
            &"0".repeat(64),
        )
        .is_err());
        drop((first_pin, second_pin));
        assert_eq!(fs::read(&path).unwrap(), b"verified complete artifact");
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0);
            }
        }
    }
    fn trusted_sid(sid: PSID) -> bool {
        !sid.is_null()
            && unsafe {
                IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            }
    }
    fn protected_acl(file: &File, require_protected: bool) -> Result<(), String> {
        let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        let _descriptor = Descriptor(descriptor);
        if code != 0 || !trusted_sid(owner) || dacl.is_null() {
            return Err("ELEVATED_STAGE_OWNER_OR_ACL".into());
        }
        let (mut control, mut revision) = (0, 0);
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err("ELEVATED_STAGE_DESCRIPTOR".into());
        }
        if require_protected && control & SE_DACL_PROTECTED == 0 {
            return Err("ELEVATED_STAGE_INHERITANCE".into());
        }
        let count = unsafe { (*dacl).AceCount };
        if count != 2 {
            return Err("ELEVATED_STAGE_ACL_SHAPE".into());
        }
        let mut has_admin = false;
        let mut has_system = false;
        for index in 0..count as u32 {
            let mut ace = null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Err("ELEVATED_STAGE_ACE".into());
            }
            let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
            let sid = (&allowed.SidStart as *const u32) as PSID;
            if allowed.Header.AceType != 0 || allowed.Mask != FILE_ALL_ACCESS || !trusted_sid(sid) {
                return Err("ELEVATED_STAGE_WRITABLE_OR_UNKNOWN".into());
            }
            has_admin |= unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0;
            has_system |= unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0;
        }
        if !has_admin || !has_system {
            return Err("ELEVATED_STAGE_TRUSTEES".into());
        }
        Ok(())
    }
    fn create_protected_directory(path: &Path) -> Result<File, String> {
        let sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err("ELEVATED_STAGE_SDDL".into());
        }
        let _descriptor = Descriptor(descriptor);
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let success = unsafe { CreateDirectoryW(wide(path)?.as_ptr(), &attrs) };
        if success == 0
            && std::io::Error::last_os_error().raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32)
        {
            return Err("ELEVATED_STAGE_CREATE_DENIED".into());
        }
        let file = lock(path, true)?;
        protected_acl(&file, true)?;
        Ok(file)
    }
    fn program_data() -> Result<PathBuf, String> {
        let mut path = null_mut();
        let result =
            unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut path) };
        if result < 0 || path.is_null() {
            if !path.is_null() {
                unsafe {
                    CoTaskMemFree(path.cast());
                }
            }
            return Err("PROGRAM_DATA_UNAVAILABLE".into());
        }
        let mut len = 0;
        while len < 32768 && unsafe { *path.add(len) } != 0 {
            len += 1;
        }
        let value = if len == 32768 {
            Err("PROGRAM_DATA_INVALID".into())
        } else {
            Ok(PathBuf::from(String::from_utf16_lossy(unsafe {
                slice::from_raw_parts(path, len)
            })))
        };
        unsafe {
            CoTaskMemFree(path.cast());
        }
        value
    }
    pub(super) fn prepare(
        core: &Path,
        config: Option<(&Path, &str)>,
    ) -> Result<LaunchIntegrity, String> {
        let dir = core.parent().ok_or("CORE_DIRECTORY_MISSING")?;
        let mut source_locks = lock_ancestors(core)?;
        let mut resources = Vec::new();
        for name in ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"] {
            let (size, hash) = compiled_artifact_identity(name)?;
            let file = verified_file(&dir.join(name), Some(size), &hash)?;
            resources.push((name, size, hash, file));
        }
        let mut config_file = if let Some((path, hash)) = config {
            source_locks.extend(lock_ancestors(path)?);
            Some(verified_file(path, None, hash)?)
        } else {
            None
        };
        if !is_process_elevated()? {
            source_locks.extend(resources.into_iter().map(|(_, _, _, file)| file));
            if let Some(file) = config_file {
                source_locks.push(file);
            }
            return Ok(LaunchIntegrity {
                core: core.to_path_buf(),
                config: config.map(|(p, _)| p.to_path_buf()),
                _files: source_locks,
                staged_config: false,
            });
        }
        // No elevated binary/config execution from a user-writable location.
        let base = program_data()?.join("VKarmani-Protected-Runtime");
        let mut pinned = lock_ancestors(&base)?;
        pinned.push(create_protected_directory(&base)?);
        let package = base.join(sha256_hex_bytes(COMPILED_CORE_MANIFEST.as_bytes()));
        pinned.push(create_protected_directory(&package)?);
        for (name, size, hash, source) in &mut resources {
            let destination = package.join(*name);
            let target = stage_verified_artifact(source, &destination, *size, hash)?;
            protected_acl(&target, false)?;
            pinned.push(target);
        }
        let staged_config = if let Some((_, hash)) = config {
            let path = package.join(format!(
                "runtime-{}-{}.json",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            let mut target = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| "STAGE_CONFIG_CREATE")?;
            let write_result = std::io::copy(
                config_file.as_mut().ok_or("STAGE_CONFIG_SOURCE")?,
                &mut target,
            )
            .map_err(|_| "STAGE_CONFIG_COPY")
            .and_then(|_| target.sync_all().map_err(|_| "STAGE_CONFIG_FLUSH"));
            drop(target);
            if let Err(error) = write_result {
                let _ = fs::remove_file(&path);
                return Err(error.into());
            }
            let verified = verified_file(&path, None, hash).and_then(|file| {
                protected_acl(&file, false)?;
                Ok(file)
            });
            let target = match verified {
                Ok(file) => file,
                Err(error) => {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
            };
            pinned.push(target);
            Some(path)
        } else {
            None
        };
        Ok(LaunchIntegrity {
            core: package.join("xray.exe"),
            config: staged_config,
            _files: pinned,
            staged_config: config.is_some(),
        })
    }
}

pub(crate) fn lock_runtime_parent_paths(path: &Path) -> Result<Vec<File>, String> {
    #[cfg(target_os = "windows")]
    {
        windows::lock_ancestors(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        Ok(vec![])
    }
}
pub(crate) fn ensure_safe_log_directory(path: &Path) -> Result<Vec<File>, String> {
    if !path.is_absolute() {
        return Err("LOG_ABSOLUTE_PATH_REQUIRED".into());
    }
    match fs::symlink_metadata(path) {
        Ok(_) => lock_runtime_parent_paths(&path.join(".log-directory-lease")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or("LOG_PARENT_REQUIRED")?;
            let _parents = ensure_safe_log_directory(parent)?;
            match fs::create_dir(path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err("LOG_DIRECTORY_CREATE".into()),
            }
            lock_runtime_parent_paths(&path.join(".log-directory-lease"))
        }
        Err(_) => Err("LOG_DIRECTORY_UNAVAILABLE".into()),
    }
}
pub(crate) fn write_new_runtime_config(path: &Path, content: &[u8]) -> Result<(), String> {
    let _parents = lock_runtime_parent_paths(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "CONFIG_CREATE_NEW_FAILED")?;
    let result = file.write_all(content).and_then(|_| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
        return Err("CONFIG_WRITE_FAILED".into());
    }
    Ok(())
}
pub(crate) fn prepare_core_launch(
    core: &Path,
    config: Option<(&Path, &str)>,
) -> Result<LaunchIntegrity, String> {
    #[cfg(target_os = "windows")]
    {
        windows::prepare(core, config)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (core, config);
        Err("WINDOWS_RUNTIME_REQUIRED".into())
    }
}
pub(crate) fn read_verified_runtime_config(path: &Path, hash: &str) -> Result<Value, String> {
    #[cfg(target_os = "windows")]
    {
        windows::read_config(path, hash)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, hash);
        Err("WINDOWS_RUNTIME_REQUIRED".into())
    }
}
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    #[test]
    fn runtime_config_create_new_preserves_existing_file_and_flushes_owned_bytes() {
        let dir = std::env::temp_dir().join(format!("vkarmani-new-config-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("config.json");
        fs::write(&path, b"last-good").unwrap();
        assert!(write_new_runtime_config(&path, b"replace").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"last-good");
        fs::remove_file(&path).unwrap();
        write_new_runtime_config(&path, b"new-native").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new-native");
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn compiled_resource_identity_is_not_replaceable_by_neighbor_manifest() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../resources/core/windows");
        let pinned = prepare_core_launch(&root.join("xray.exe"), None).unwrap();
        assert!(pinned.core.is_file());
        assert!(compiled_artifact_identity("evil.dll").is_err());
    }
    #[test]
    fn attacker_replaced_neighbor_manifest_cannot_authorize_modified_artifact() {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-manifest-adversary-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("geoip.dat");
        fs::write(&path, b"modified").unwrap();
        fs::write(dir.join("core-manifest.json"),serde_json::to_vec(&json!({"files":[{"file":"geoip.dat","size":8,"sha256":sha256_hex_bytes(b"modified")}]})).unwrap()).unwrap();
        assert!(verify_core_manifest_artifact(&path, "geoip.dat").is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_file(dir.join("core-manifest.json")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn retained_config_file_handle_blocks_write_until_guard_release() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../resources/core/windows");
        let path = std::env::temp_dir().join(format!(
            "vkarmani-locked-config-{}.json",
            std::process::id()
        ));
        fs::write(&path, b"{}").unwrap();
        let pin = prepare_core_launch(
            &root.join("xray.exe"),
            Some((&path, &sha256_hex_bytes(b"{}"))),
        )
        .unwrap();
        let config = pin.config.clone().unwrap();
        assert!(OpenOptions::new().write(true).open(&config).is_err());
        drop(pin);
        fs::remove_file(&path).unwrap();
    }
    #[test]
    fn config_hash_mismatch_rejects_before_execution() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../resources/core/windows");
        let path =
            std::env::temp_dir().join(format!("vkarmani-integrity-{}.json", std::process::id()));
        fs::write(&path, b"{}").unwrap();
        assert!(
            prepare_core_launch(&root.join("xray.exe"), Some((&path, &"0".repeat(64)))).is_err()
        );
        fs::remove_file(path).unwrap();
    }
}
