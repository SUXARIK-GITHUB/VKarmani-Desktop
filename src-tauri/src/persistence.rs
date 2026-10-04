use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "windows")]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide = |path: &Path| -> std::io::Result<Vec<u16>> {
        let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
        if text.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NUL path",
            ));
        }
        text.push(0);
        Ok(text)
    };
    let src = wide(source)?;
    let dst = wide(destination)?;
    // One same-directory rename with replacement/write-through, never the
    // old delete-then-rename fallback. The new file inherits its owned state
    // directory ACL. ReplaceFileW without a recovery backup can lose the old
    // filename on ERROR_UNABLE_TO_MOVE_REPLACEMENT; do not use that sequence.
    let ok = unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), 0x1 | 0x8) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

pub(crate) fn atomic_write_text(path: &Path, payload: &str, context: &str) -> Result<(), String> {
    if payload.len() as u64 > ENCRYPTED_STATE_MAX_BYTES {
        return Err(format!("{context}: файл состояния слишком большой"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{context}: нет каталога состояния"))?;
    fs::create_dir_all(parent).map_err(|error| format!("{context}: создание каталога: {error}"))?;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or_default();
    let temporary = parent.join(format!(
        ".vkarmani-state-{}-{nonce}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("{context}: создание временного файла: {error}"))?;
    let result = (|| {
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        // This exact temporary file was created above by this invocation.
        // The old target is never explicitly removed, even on replace failure.
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| format!("{context}: atomic replacement: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_replacement_and_failure_leave_last_good_target_intact() {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-state-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let target = dir.join("synthetic.json");
        atomic_write_text(&target, "old", "test").unwrap();
        atomic_write_text(&target, "new", "test").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        let locked = OpenOptions::new().read(true).open(&target).unwrap();
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let no_delete_share = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&target)
                .unwrap();
            assert!(atomic_write_text(&target, "must-not-replace", "test").is_err());
            assert_eq!(fs::read_to_string(&target).unwrap(), "new");
            drop(no_delete_share);
        }
        drop(locked);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1); // no partial temp remains
        fs::remove_file(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn dpapi_round_trip_rejects_corruption_without_plaintext_fallback() {
        #[cfg(target_os = "windows")]
        {
            let secret = "synthetic-credential Россия 🌍";
            let encrypted = encrypt_access_key(secret).unwrap();
            assert!(!encrypted.contains(secret));
            assert_eq!(decrypt_access_key(&encrypted).unwrap(), secret);
            let mut bytes = general_purpose::STANDARD.decode(encrypted).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x80;
            assert!(decrypt_access_key(&general_purpose::STANDARD.encode(bytes)).is_err());
            assert!(decrypt_access_key("not-base64!").is_err());
        }
    }
    #[test]
    fn large_unicode_dpapi_payload_exceeds_old_ciphertext_limit_without_truncation() {
        #[cfg(target_os = "windows")]
        {
            let plaintext = "Россия 🌍".repeat(180_000);
            assert!(plaintext.len() > CLIENT_STATE_MAX_BYTES as usize);
            assert!(plaintext.len() < SENSITIVE_CLIENT_STATE_MAX_BYTES as usize);
            let encrypted = encrypt_access_key(&plaintext).unwrap();
            assert!(encrypted.len() > plaintext.len());
            assert!(encrypted.len() < ENCRYPTED_STATE_MAX_BYTES as usize);
            assert_eq!(decrypt_access_key(&encrypted).unwrap(), plaintext);
        }
    }
}
