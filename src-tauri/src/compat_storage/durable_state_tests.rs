#![cfg(windows)]
use super::*;

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-state-v2-{}-{}",
            std::process::id(),
            random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn store(&self) -> DurableStore {
        DurableStore::at(self.root.clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let expected = std::env::temp_dir().canonicalize().unwrap();
        let resolved = self.root.canonicalize().unwrap();
        assert_eq!(resolved.parent(), Some(expected.as_path()));
        assert!(resolved
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("vkarmani-state-v2-"));
        fs::remove_dir_all(resolved).unwrap(); // Exact random synthetic fixture only.
    }
}
fn patch(
    snapshot: &DurableSnapshot,
    id: &str,
    scope: &str,
    key: &str,
    value: Option<Value>,
) -> StatePatch {
    StatePatch {
        generation: snapshot.generation.clone(),
        expected_revision: snapshot.revision.clone(),
        expected_session_generation: snapshot.payload.session_generation.to_string(),
        operation_id: id.into(),
        changes: vec![StateChange {
            scope: scope.into(),
            key: key.into(),
            value,
        }],
    }
}
fn synthetic_key(suffix: &str) -> String {
    format!("{VKARMANI_ACCESS_KEY_PREFIX}synthetic-{suffix}")
}

#[test]
fn rollback_carrier_retains_exact_v2_originals_and_unknown_fields_across_restarts() {
    let f = Fixture::new();
    let store = f.store();
    let original = Envelope {
        schema_version: 2, generation: "a".repeat(48), revision: 7, updated_at: "0".into(),
        operations: Vec::new(),
        payload: DurablePayload {
            public_state: serde_json::from_value(json!({"settings":{"language":"en","future076Unknown":{"keep":true}},"favoriteServerIds":["server-a"],"selectedServerId":"server-a","futureRoot":{"keep":true}})).unwrap(),
            protected: serde_json::from_value(json!({"futureProtected":{"keep":true},"lastKnownServers":[{"id":"server-a","rawUri":"synthetic-private"}]})).unwrap(),
            access_key: Some(synthetic_key("rollback")), ..Default::default()
        },
    };
    let cipher = encode_envelope(&original).unwrap();
    fs::write(store.primary(), &cipher).unwrap();
    fs::write(store.backup(), &cipher).unwrap();
    fs::write(f.root.join("state-v2.initialized"), V2_MARKER).unwrap();
    let snapshot = store.load().unwrap();
    let archive = f.root.join("rollback-083-originals");
    assert_eq!(fs::read(archive.join(V2_NAME)).unwrap(), cipher.as_bytes());
    assert_eq!(
        fs::read(archive.join("client-state-v2.dpapi.lkg.dpapi")).unwrap(),
        cipher.as_bytes()
    );
    let saved = store
        .patch(patch(
            &snapshot,
            "old-ui-edit",
            "public",
            "settings",
            Some(json!({"language":"ru"})),
        ))
        .unwrap()
        .snapshot;
    assert_eq!(
        saved.payload.public_state["settings"]["future076Unknown"]["keep"],
        true
    );
    assert_eq!(saved.payload.public_state["futureRoot"]["keep"], true);
    assert_eq!(saved.payload.protected["futureProtected"]["keep"], true);
    assert_eq!(
        saved.payload.protected["lastKnownServers"][0]["rawUri"],
        "synthetic-private"
    );
    let restarted = f.store().load().unwrap();
    assert_eq!(restarted.revision, saved.revision);
    assert_eq!(restarted.payload.access_key, original.payload.access_key);
    assert_eq!(
        restarted.payload.public_state["favoriteServerIds"],
        json!(["server-a"])
    );
    assert_eq!(
        restarted.payload.public_state["selectedServerId"],
        "server-a"
    );
    assert_eq!(fs::read(archive.join(V2_NAME)).unwrap(), cipher.as_bytes());
    assert!(!fs::read_to_string(store.primary())
        .unwrap()
        .contains("synthetic-private"));
}

#[test]
fn incomplete_or_tampered_rollback_archive_cannot_authorize_overwrite() {
    let f = Fixture::new();
    let store = f.store();
    let first = store.load().unwrap();
    let primary = fs::read(store.primary()).unwrap();
    let dir = f.root.join("rollback-083-originals");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(V2_NAME), "synthetic-conflicting-original").unwrap();
    assert!(store
        .patch(patch(
            &first,
            "must-fail",
            "public",
            "selectedServerId",
            Some(json!("new"))
        ))
        .is_err());
    assert_eq!(fs::read(store.primary()).unwrap(), primary);
    assert_eq!(
        fs::read_to_string(dir.join(V2_NAME)).unwrap(),
        "synthetic-conflicting-original"
    );
}

#[test]
fn history_is_optional_bounded_secret_free_and_preserves_other_state() {
    let f = Fixture::new();
    let store = f.store();
    let snapshot = store.load().unwrap();
    let row = json!({"id":"a".repeat(32),"startedAtMs":"0","durationSeconds":10,"mode":"tun","status":"current"});
    let saved = store
        .patch(patch(
            &snapshot,
            "history-one",
            "public",
            "sessionHistory",
            Some(json!([row.clone()])),
        ))
        .unwrap()
        .snapshot;
    assert_eq!(
        store.load().unwrap().payload.public_state["sessionHistory"][0]["durationSeconds"],
        10
    );
    let original = fs::read(store.primary()).unwrap();
    for key in [
        "accessKey",
        "subscriptionUrl",
        "runtimeTemplate",
        "serverLabel",
        "host",
    ] {
        let mut bad = row.clone();
        bad[key] = json!("synthetic-secret");
        assert!(store
            .patch(patch(
                &saved,
                "history-bad",
                "public",
                "sessionHistory",
                Some(json!([bad]))
            ))
            .is_err());
        assert_eq!(fs::read(store.primary()).unwrap(), original);
    }
    let exported = store
        .export_legacy(&saved.generation, &saved.revision)
        .unwrap();
    let legacy: Value = serde_json::from_str(
        &decrypt_access_key(
            &fs::read_to_string(exported.join("client-state-v1.json.dpapi")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(legacy["sessionHistory"][0], row);
    assert!(exported.join("COMPLETE.json").is_file());
    assert_eq!(fs::read(store.primary()).unwrap(), original);
    let oversized = json!(vec![row; 129]);
    assert!(store
        .patch(patch(
            &saved,
            "history-limit",
            "public",
            "sessionHistory",
            Some(oversized)
        ))
        .is_err());
    assert_eq!(fs::read(store.primary()).unwrap(), original);
}

#[test]
fn v2_migration_keeps_legacy_originals_and_unknown_fields_and_secrets_encrypted() {
    let f = Fixture::new();
    let store = f.store();
    let public = json!({"settings":{"language":"en","futureSetting":{"keep":true}},"favoriteServerIds":["one"],"futureRoot":{"keep":true},"lastKnownServers":[{"id":"one","rawUri":"synthetic-private-value","runtimeTemplate":{"family":"xray","outbound":{}}}]});
    fs::write(f.root.join("client-state-v1.json"), public.to_string()).unwrap();
    fs::write(
        f.root.join("sensitive-client-state-v1.dpapi"),
        encrypt_access_key(r#"{"futureProtected":{"keep":true}}"#).unwrap(),
    )
    .unwrap();
    fs::write(
        f.root.join("access-key.dpapi"),
        encrypt_access_key(&synthetic_key("one")).unwrap(),
    )
    .unwrap();
    let before = [
        "client-state-v1.json",
        "sensitive-client-state-v1.dpapi",
        "access-key.dpapi",
    ]
    .map(|name| fs::read(f.root.join(name)).unwrap());
    let s = store.load().unwrap();
    assert!(!s.read_only);
    assert_eq!(s.revision, "0");
    assert_eq!(s.payload.public_state["futureRoot"]["keep"], true);
    assert_eq!(s.payload.protected["futureProtected"]["keep"], true);
    assert!(s.payload.public_state["lastKnownServers"][0]
        .get("rawUri")
        .is_none());
    assert_eq!(
        s.payload.protected["lastKnownServers"][0]["rawUri"],
        "synthetic-private-value"
    );
    for (index, name) in [
        "client-state-v1.json",
        "sensitive-client-state-v1.dpapi",
        "access-key.dpapi",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(fs::read(f.root.join(name)).unwrap(), before[index]);
    }
    let cipher = fs::read_to_string(store.primary()).unwrap();
    assert!(!cipher.contains("synthetic-private-value"));
    let updated = store
        .patch(patch(
            &s,
            "merge-settings",
            "public",
            "settings",
            Some(json!({"language":"ru"})),
        ))
        .unwrap()
        .snapshot;
    assert_eq!(
        updated.payload.public_state["settings"]["futureSetting"]["keep"],
        true
    );
    let exported = store
        .export_legacy(&updated.generation, &updated.revision)
        .unwrap();
    assert!(exported.join("COMPLETE.json").is_file());
    assert!(!exported.join("client-state-v1.json").exists());
    // Decode only into a separate synthetic activation fixture; the rollback
    // package itself never creates a plaintext public/unknown-field backup.
    let activation = f.root.join("synthetic-activation");
    fs::create_dir(&activation).unwrap();
    fs::write(
        activation.join("client-state-v1.json"),
        decrypt_access_key(
            &fs::read_to_string(exported.join("client-state-v1.json.dpapi")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        read_client_state_at(&activation.join("client-state-v1.json"), false)
            .unwrap()
            .values["futureRoot"]["keep"],
        true
    );
    assert_eq!(
        read_client_state_at(&exported.join("sensitive-client-state-v1.dpapi"), true)
            .unwrap()
            .values["lastKnownServers"][0]["rawUri"],
        "synthetic-private-value"
    );
    assert_eq!(
        decrypt_access_key(&fs::read_to_string(exported.join("access-key.dpapi")).unwrap())
            .unwrap(),
        synthetic_key("one")
    );
}

#[test]
fn stale_cas_and_reused_operation_id_never_overwrite_committed_data() {
    let f = Fixture::new();
    let store = f.store();
    let first = store.load().unwrap();
    let request = patch(
        &first,
        "first",
        "public",
        "selectedServerId",
        Some(json!("one")),
    );
    let committed = store.patch(request.clone()).unwrap();
    assert_eq!(committed.snapshot.revision, "1");
    assert!(store.patch(request.clone()).unwrap().deduplicated);
    let mut reused = request.clone();
    reused.changes[0].value = Some(json!("bad"));
    assert_eq!(
        store.patch(reused).err().unwrap().code,
        "STATE_OPERATION_REUSED"
    );
    let mut stale = request;
    stale.operation_id = "stale".into();
    let error = store.patch(stale).err().unwrap();
    assert_eq!(error.code, "STATE_CONFLICT");
    assert_eq!(error.current_revision.as_deref(), Some("1"));
    let before = fs::read(store.primary()).unwrap();
    let noop = store
        .patch(patch(
            &committed.snapshot,
            "no-op",
            "public",
            "selectedServerId",
            Some(json!("one")),
        ))
        .unwrap();
    assert_eq!(noop.snapshot.revision, "1");
    assert_eq!(fs::read(store.primary()).unwrap(), before);
}

#[test]
fn deleted_v2_cannot_silently_resurrect_stale_legacy_state() {
    let f = Fixture::new();
    let store = f.store();
    fs::write(
        f.root.join("client-state-v1.json"),
        r#"{"selectedServerId":"old"}"#,
    )
    .unwrap();
    let original = store.load().unwrap();
    store
        .patch(patch(
            &original,
            "newer",
            "public",
            "selectedServerId",
            Some(json!("new")),
        ))
        .unwrap();
    fs::remove_file(store.primary()).unwrap();
    fs::remove_file(store.backup()).unwrap();
    let recovery = store.load().unwrap();
    assert!(recovery.read_only);
    assert!(!store.primary().exists());
    assert_eq!(recovery.payload.public_state["selectedServerId"], "old");
    assert!(store
        .patch(patch(
            &recovery,
            "must-not-restore",
            "public",
            "selectedServerId",
            Some(json!("bad"))
        ))
        .is_err());
    store.recover(&recovery.recovery_token.unwrap()).unwrap();
    assert_eq!(
        fs::read_to_string(f.root.join("client-state-v1.json")).unwrap(),
        r#"{"selectedServerId":"old"}"#
    );
}

#[test]
fn full_u64_stamps_are_strings_on_the_renderer_wire() {
    let f = Fixture::new();
    let mut s = f.store().load().unwrap();
    s.revision = u64::MAX.to_string();
    s.payload.session_generation = u64::MAX;
    let wire = serde_json::to_value(s).unwrap();
    assert_eq!(wire["revision"], u64::MAX.to_string());
    assert_eq!(wire["payload"]["sessionGeneration"], u64::MAX.to_string());
}

#[test]
fn corrupt_future_locked_and_failed_backup_cannot_reset_state() {
    let f = Fixture::new();
    let store = f.store();
    fs::write(f.root.join("client-state-v1.json"), "{broken-legacy").unwrap();
    assert!(store.load().is_err());
    assert!(!store.primary().exists());
    fs::write(f.root.join("client-state-v1.json"), "{}").unwrap();
    let s = store.load().unwrap();
    let cipher = fs::read(store.primary()).unwrap();
    fs::remove_file(store.backup()).unwrap();
    fs::create_dir(store.backup()).unwrap();
    assert!(store
        .patch(patch(
            &s,
            "blocked-backup",
            "public",
            "favoriteServerIds",
            Some(json!(["one"]))
        ))
        .is_err());
    assert_eq!(fs::read(store.primary()).unwrap(), cipher);
    fs::remove_dir(store.backup()).unwrap();
    fs::write(store.backup(), &cipher).unwrap();
    let future = encrypt_access_key(r#"{"schemaVersion":999}"#).unwrap();
    fs::write(store.primary(), &future).unwrap();
    assert_eq!(store.load().err().unwrap().code, "STATE_UNSUPPORTED_SCHEMA");
    assert_eq!(fs::read_to_string(store.primary()).unwrap(), future);
    fs::write(store.primary(), &cipher).unwrap();
    use std::os::windows::fs::OpenOptionsExt;
    let blocker = OpenOptions::new()
        .write(true)
        .share_mode(4)
        .open(store.primary())
        .unwrap();
    assert!(store.load().is_err());
    drop(blocker);
    assert_eq!(fs::read(store.primary()).unwrap(), cipher);
}

#[test]
fn recovery_is_explicit_hash_bound_and_preserves_corrupt_original_encrypted() {
    let f = Fixture::new();
    let store = f.store();
    let s = store.load().unwrap();
    let s = store
        .patch(patch(
            &s,
            "one",
            "public",
            "selectedServerId",
            Some(json!("one")),
        ))
        .unwrap()
        .snapshot;
    let s = store
        .patch(patch(
            &s,
            "two",
            "public",
            "selectedServerId",
            Some(json!("two")),
        ))
        .unwrap()
        .snapshot;
    let bad = [0xff, 0x00, 0x80];
    fs::write(store.primary(), bad).unwrap();
    let recovery = store.load().unwrap();
    assert!(recovery.read_only);
    assert_eq!(recovery.payload.public_state["selectedServerId"], "one");
    assert!(store
        .patch(patch(
            &s,
            "must-not-write",
            "public",
            "selectedServerId",
            Some(json!("bad"))
        ))
        .is_err());
    let token = recovery.recovery_token.unwrap();
    assert!(store.recover(&"0".repeat(64)).is_err());
    let restored = store.recover(&token).unwrap();
    assert!(!restored.read_only);
    assert_ne!(restored.generation, s.generation);
    assert!(store.recover(&token).is_err());
    let preserved = fs::read_dir(&f.root)
        .unwrap()
        .map(|x| x.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("state-preserved-")
        })
        .unwrap();
    assert_eq!(
        general_purpose::STANDARD
            .decode(decrypt_access_key(&fs::read_to_string(preserved).unwrap()).unwrap())
            .unwrap(),
        bad
    );
}

#[test]
fn legacy_lkg_requires_confirmation_and_does_not_rewrite_the_old_files() {
    let f = Fixture::new();
    let store = f.store();
    let path = f.root.join("client-state-v1.json");
    update_client_state_at(&path, false, "selectedServerId", Some(json!("one"))).unwrap();
    update_client_state_at(&path, false, "selectedServerId", Some(json!("two"))).unwrap();
    fs::write(&path, "broken-original").unwrap();
    let recovered = store.load().unwrap();
    assert!(recovered.read_only);
    assert!(!store.primary().exists());
    assert_eq!(recovered.payload.public_state["selectedServerId"], "one");
    store.recover(&recovered.recovery_token.unwrap()).unwrap();
    assert_eq!(fs::read_to_string(path).unwrap(), "broken-original");
    assert!(store.primary().is_file());
}

#[test]
fn credential_change_clears_old_profiles_and_legacy_secrets_even_in_lkg() {
    let f = Fixture::new();
    let store = f.store();
    let s = store.load().unwrap();
    let s = store
        .patch(patch(
            &s,
            "key-one",
            "credential",
            "accessKey",
            Some(json!(synthetic_key("one"))),
        ))
        .unwrap()
        .snapshot;
    let stale = s.clone();
    let s = store
        .patch(patch(
            &s,
            "profile-one",
            "protected",
            "lastKnownServers",
            Some(json!([{"rawUri":"synthetic-profile-one"}])),
        ))
        .unwrap()
        .snapshot;
    let s = store
        .patch(patch(
            &s,
            "key-two",
            "credential",
            "accessKey",
            Some(json!(synthetic_key("two"))),
        ))
        .unwrap()
        .snapshot;
    assert!(s.payload.protected.get("lastKnownServers").is_none());
    assert!(store
        .patch(patch(
            &stale,
            "late-profile",
            "protected",
            "lastKnownServers",
            Some(json!([]))
        ))
        .is_err());
    let s = store
        .patch(patch(&s, "logout", "credential", "accessKey", None))
        .unwrap()
        .snapshot;
    assert!(s.payload.access_key.is_none());
    fs::write(store.primary(), "broken").unwrap();
    assert!(store.load().unwrap().payload.access_key.is_none());
}

#[test]
fn a_thousand_edits_reload_conflicts_and_large_payload_bounds_are_real_io() {
    let f = Fixture::new();
    let store = f.store();
    let mut s = store.load().unwrap();
    let started = Instant::now();
    for i in 0..1000 {
        let old = s.clone();
        s = store
            .patch(patch(
                &s,
                &format!("edit-{i}"),
                "public",
                "selectedServerId",
                Some(json!(format!("server-{i}"))),
            ))
            .unwrap()
            .snapshot;
        assert_eq!(s.revision, (i + 1).to_string());
        if i % 17 == 0 {
            assert!(store
                .patch(patch(
                    &old,
                    &format!("stale-{i}"),
                    "public",
                    "favoriteServerIds",
                    Some(json!(["stale"]))
                ))
                .is_err());
        }
        s = DurableStore::at(f.root.clone()).load().unwrap();
        assert_eq!(s.revision, (i + 1).to_string());
    }
    println!(
        "STATE_V2_1000_EDITS durationSeconds={}",
        started.elapsed().as_secs_f64()
    );
    let before = fs::read(store.primary()).unwrap();
    assert!(store
        .patch(patch(
            &s,
            "too-large",
            "protected",
            "lastKnownServers",
            Some(json!([
                "x".repeat(SENSITIVE_CLIENT_STATE_MAX_BYTES as usize)
            ]))
        ))
        .is_err());
    assert_eq!(fs::read(store.primary()).unwrap(), before);
    let large = Instant::now();
    store
        .patch(patch(
            &s,
            "large-valid",
            "protected",
            "lastKnownServers",
            Some(json!(["x".repeat(2 * 1024 * 1024)])),
        ))
        .unwrap();
    println!(
        "STATE_V2_2MIB_COMMIT durationSeconds={}",
        large.elapsed().as_secs_f64()
    );
}

#[test]
fn concurrent_compare_and_swap_has_one_winner_without_lost_keys() {
    let f = Fixture::new();
    let s = f.store().load().unwrap();
    let barrier = std::sync::Barrier::new(8);
    let wins = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for i in 0..8 {
            let (root, s, barrier, wins) = (&f.root, &s, &barrier, &wins);
            scope.spawn(move || {
                barrier.wait();
                if DurableStore::at(root.clone())
                    .patch(patch(
                        s,
                        &format!("race-{i}"),
                        "public",
                        "selectedServerId",
                        Some(json!(i.to_string())),
                    ))
                    .is_ok()
                {
                    wins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(wins.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(f.store().load().unwrap().revision, "1");
}

#[test]
fn interrupted_precommit_child_releases_lease_and_temp_is_not_authority() {
    let _guard = HELPER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new();
    let store = f.store();
    let first = store.load().unwrap();
    let primary = fs::read(store.primary()).unwrap();
    let lkg = fs::read(store.backup()).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "compat_storage::durable::tests::cross_process_fixture_entry",
            "--ignored",
            "--nocapture",
        ])
        .env("VKARMANI_V2_OWNED_FIXTURE", &f.root)
        .env("VKARMANI_V2_OWNED_PHASE", "precommit-abort");
    assert!(
        run_command_with_timeout(command, Duration::from_secs(15), "owned precommit abort")
            .is_err()
    );
    let orphan = f.root.join(".vkarmani-state-owned-abort.tmp");
    assert_eq!(
        fs::read(&orphan).unwrap(),
        b"synthetic-uncommitted-ciphertext"
    );
    let loaded = store.load().unwrap();
    assert_eq!(loaded.generation, first.generation);
    assert_eq!(loaded.revision, first.revision);
    assert_eq!(fs::read(store.primary()).unwrap(), primary);
    assert_eq!(fs::read(store.backup()).unwrap(), lkg);
    assert!(orphan.exists()); // Never promote/delete an uncommitted file by prefix.
}
#[test]
fn failed_primary_commit_does_not_ack_or_deduplicate_the_uncommitted_operation() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let store = f.store();
    let first = store.load().unwrap();
    let primary = fs::read(store.primary()).unwrap();
    let request = patch(
        &first,
        "owned-retry",
        "public",
        "selectedServerId",
        Some(json!("new-server")),
    );
    let blocker = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(store.primary())
        .unwrap();
    assert!(store.patch(request.clone()).is_err());
    assert_eq!(fs::read(store.primary()).unwrap(), primary);
    assert_eq!(store.load().unwrap().revision, first.revision);
    drop(blocker);
    let committed = store.patch(request.clone()).unwrap();
    assert!(!committed.deduplicated);
    assert_eq!(committed.snapshot.revision, "1");
    assert!(store.patch(request).unwrap().deduplicated);
}
#[test]
fn a_separate_process_cannot_bypass_the_native_writer_lease() {
    let f = Fixture::new();
    let _lease = WriterLease::acquire(&f.root).unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "compat_storage::durable::tests::cross_process_fixture_entry",
            "--ignored",
            "--nocapture",
        ])
        .env("VKARMANI_V2_OWNED_FIXTURE", &f.root)
        .output()
        .unwrap();
    assert!(result.status.success(), "owned child fixture failed");
}
#[test]
#[ignore = "owned lease/precommit-abort entry exercised by parent tests"]
fn cross_process_fixture_entry() {
    let root = PathBuf::from(
        std::env::var_os("VKARMANI_V2_OWNED_FIXTURE")
            .expect("only owned parent fixture may invoke"),
    );
    assert_eq!(
        root.canonicalize().unwrap().parent(),
        Some(std::env::temp_dir().canonicalize().unwrap().as_path())
    );
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("vkarmani-state-v2-"));
    if std::env::var("VKARMANI_V2_OWNED_PHASE").as_deref() == Ok("precommit-abort") {
        let _lease = WriterLease::acquire(&root).unwrap();
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(".vkarmani-state-owned-abort.tmp"))
            .unwrap();
        temporary
            .write_all(b"synthetic-uncommitted-ciphertext")
            .unwrap();
        temporary.sync_all().unwrap();
        std::process::exit(31);
    }
    assert_eq!(
        DurableStore::at(root).load().err().unwrap().code,
        "STATE_WRITER_BUSY"
    );
}
