use super::*;

// Journals and durable state must share the same path guards and bounded
// sharing-conflict policy. No delete-first or generic access-denied fallback.
pub(crate) fn atomic_write_text(path: &Path, payload: &str, context: &str) -> Result<(), String> {
    crate::compat_storage::atomic_write_state_text_with_limit(
        path,
        payload,
        ENCRYPTED_STATE_MAX_BYTES,
    )
    .map_err(|error| format!("{context}: atomic replacement: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(windows)]
    fn production_journal_writer_rejects_hardlinked_targets() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-journal-guard-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let original = root.join("synthetic-original.dpapi");
        let target = root.join("system-proxy-ownership-v2.dpapi");
        fs::write(&original, "original").unwrap();
        fs::hard_link(&original, &target).unwrap();
        let result = atomic_write_text(&target, "must-not-write", "Proxy journal");
        let actual = fs::read_to_string(&target).unwrap();
        let preserved = fs::read_to_string(&original).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_file(original).unwrap();
        fs::remove_dir(root).unwrap();
        assert!(result.is_err(), "unsafe journal target must be refused");
        assert_eq!(actual, "original");
        assert_eq!(preserved, "original");
    }

    #[test]
    #[cfg(windows)]
    fn production_journal_writer_rejects_junction_parents() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-journal-parent-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let outside = root.join("synthetic-other-owner");
        fs::create_dir(&outside).unwrap();
        let link = root.join("linked-parent");
        let mut command = Command::new(
            system_program("reg")
                .unwrap()
                .parent()
                .unwrap()
                .join("cmd.exe"),
        );
        command
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside);
        run_command_with_timeout(
            command,
            Duration::from_secs(3),
            "synthetic journal junction",
        )
        .unwrap();
        let actual_path = outside.join("owned-tun-routes-v1.dpapi");
        fs::write(&actual_path, "original").unwrap();
        let result = atomic_write_text(
            &link.join("owned-tun-routes-v1.dpapi"),
            "must-not-write",
            "Owned routes",
        );
        let actual = fs::read_to_string(&actual_path).unwrap();
        fs::remove_dir(link).unwrap();
        fs::remove_file(actual_path).unwrap();
        fs::remove_dir(outside).unwrap();
        fs::remove_dir(root).unwrap();
        assert!(
            result.is_err(),
            "a journal must not escape through a junction"
        );
        assert_eq!(actual, "original");
    }
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
