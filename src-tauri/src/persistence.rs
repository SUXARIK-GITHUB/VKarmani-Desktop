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
    fn concurrent_journal_and_state_replacements_keep_complete_dpapi_values() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-parallel-journals-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let pins = lock_runtime_parent_paths(&root.join("synthetic-config.json")).unwrap();
        for name in [
            "owned-tun-routes-v1.dpapi",
            "system-proxy-ownership-v2.dpapi",
            "client-state-v2.dpapi",
        ] {
            let path = root.join(name);
            atomic_write_text(&path, &encrypt_access_key("initial").unwrap(), "synthetic").unwrap();
            let start = std::sync::Barrier::new(3);
            let successes = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|scope| {
                for writer in 0..2 {
                    let path = &path;
                    let start = &start;
                    let successes = &successes;
                    scope.spawn(move || {
                        start.wait();
                        for revision in 0..8 {
                            let cipher =
                                encrypt_access_key(&format!("writer-{writer}-{revision}")).unwrap();
                            match atomic_write_text(path, &cipher, "synthetic") {
                                Ok(()) => {
                                    successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                                Err(error) => assert!(
                                    error.contains("os error 32") || error.contains("os error 5"),
                                    "{error}"
                                ),
                            }
                        }
                    });
                }
                start.wait();
                for _ in 0..16 {
                    let cipher = crate::compat_storage::read_state_file(&path, 32768)
                        .unwrap()
                        .unwrap();
                    let value = decrypt_access_key(&cipher).unwrap();
                    assert!(value == "initial" || value.starts_with("writer-"));
                }
            });
            assert!(successes.load(std::sync::atomic::Ordering::SeqCst) > 0);
            atomic_write_text(
                &path,
                &encrypt_access_key("recovered").unwrap(),
                "synthetic",
            )
            .unwrap();
            assert_eq!(
                decrypt_access_key(&fs::read_to_string(&path).unwrap()).unwrap(),
                "recovered"
            );
            fs::remove_file(path).unwrap();
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        drop(pins);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn directory_access_matrix_for_journal_replacement() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let root = std::env::temp_dir().join(format!(
            "vkarmani-directory-access-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let target = root.join("journal.dpapi");
        for (label, access, sharing, works) in [
            ("old-read", FILE_GENERIC_READ, FILE_SHARE_READ, false),
            (
                "metadata-read",
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                FILE_SHARE_READ,
                false,
            ),
            (
                "read-write-sharing",
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                true,
            ),
        ] {
            let guard = OpenOptions::new()
                .access_mode(access)
                .share_mode(sharing)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&root)
                .unwrap();
            let result = atomic_write_text(&target, "synthetic", "Owned routes");
            println!("{label}: {result:?}");
            drop(guard);
            if target.exists() {
                fs::remove_file(&target).unwrap();
            }
            if works {
                assert!(result.is_ok());
            } else {
                assert!(result.unwrap_err().contains("os error 32"));
            }
        }
        fs::remove_dir(root).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn journal_replacement_with_retained_runtime_directory_guards() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-retained-journal-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("owned-tun-routes-v1.dpapi");
        let guards = lock_runtime_parent_paths(&root.join("synthetic-config.json")).unwrap();
        assert!(
            fs::rename(&root, root.with_extension("moved")).is_err(),
            "directory replacement must stay blocked"
        );
        let first = atomic_write_text(
            &path,
            &encrypt_access_key("synthetic-first").unwrap(),
            "Owned routes",
        );
        let second = first.as_ref().ok().map(|_| {
            atomic_write_text(
                &path,
                &encrypt_access_key("synthetic-second").unwrap(),
                "Owned routes",
            )
        });
        drop(guards);
        let recovery = atomic_write_text(
            &path,
            &encrypt_access_key("synthetic-recovered").unwrap(),
            "Owned routes",
        );
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&root).unwrap();
        assert!(recovery.is_ok(), "write after guard release: {recovery:?}");
        assert!(
            first.is_ok(),
            "initial write while own runtime guards live: {first:?}"
        );
        assert!(second.unwrap().is_ok());
    }
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
