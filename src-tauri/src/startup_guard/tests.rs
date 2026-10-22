use super::*;
#[cfg(windows)]
#[test]
fn initial_guard_write_failure_is_an_error_without_clobbering_user_state_or_panicking() {
    use std::os::windows::fs::OpenOptionsExt;
    let path = root();
    let marker = path.join("startup-guard-v1.json");
    let original = serde_json::to_string(&record(Phase::Ready, 0, 100)).unwrap();
    fs::write(&marker, &original).unwrap();
    let user = path.join("synthetic-user-data.json");
    fs::write(&user, "preserve").unwrap();
    let blocker = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&marker)
        .unwrap();
    let result = Guard::begin(&path, 101, false);
    assert!(matches!(
        result,
        Err(StartupError {
            code: "STARTUP_GUARD_WRITE_FAILED",
            ..
        })
    ));
    drop(blocker);
    assert_eq!(fs::read_to_string(&marker).unwrap(), original);
    assert_eq!(fs::read_to_string(&user).unwrap(), "preserve");
    // The failed attempt released its exact lease; no duplicate owner remains.
    let (guard, status) = Guard::begin(&path, 102, false).unwrap();
    assert_eq!(status.mode, "normal");
    drop(guard);
    cleanup(&path);
}
#[cfg(windows)]
#[test]
fn app_admission_requires_current_normal_attempt_before_any_other_command() {
    let path = root();
    let (guard, status) = Guard::begin(&path, 100, false).unwrap();
    let id = status.attempt_id.clone().unwrap();
    let mut supervisor = StartupSupervisor {
        guard: Some(guard),
        status,
        admitted: false,
    };
    assert!(supervisor.commands_blocked());
    assert!(supervisor.admit("stale").is_err());
    assert!(supervisor.commands_blocked());
    supervisor.admit(&id).unwrap();
    assert!(!supervisor.commands_blocked());
    drop(supervisor);
    let (guard, status) = Guard::begin(&path, 101, true).unwrap();
    let id = status.attempt_id.clone().unwrap();
    let mut supervisor = StartupSupervisor {
        guard: Some(guard),
        status,
        admitted: false,
    };
    assert!(supervisor.admit(&id).is_err());
    assert!(supervisor.commands_blocked());
    drop(supervisor);
    cleanup(&path);
}
fn record(phase: Phase, failures: u8, time: u64) -> Record {
    Record {
        schema_version: 1,
        attempt_id: "a".repeat(48),
        failures,
        window_start_ms: time,
        started_ms: time,
        phase,
    }
}
#[cfg(windows)]
fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "vkarmani-startup-fixture-{}-{}",
        std::process::id(),
        crate::durable_state::random_state_id().unwrap()
    ));
    fs::create_dir(&path).unwrap();
    path
}
#[cfg(windows)]
fn cleanup(path: &Path) {
    assert!(path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("vkarmani-startup-fixture-"));
    assert_eq!(
        path.parent().unwrap().canonicalize().unwrap(),
        std::env::temp_dir().canonicalize().unwrap()
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn three_unconfirmed_attempts_latch_recovery_until_an_explicit_retry() {
    let mut prior = None;
    for n in 0..4 {
        let (next, code) =
            next_record(prior.as_ref(), 1000 + n * 100, false, "b".repeat(48)).unwrap();
        assert_eq!(next.failures, n as u8);
        assert_eq!(next.phase == Phase::Safe, n == 3);
        assert_eq!(code == "STARTUP_CRASH_LOOP", n == 3);
        prior = Some(next);
    }
    let (next, _) = next_record(prior.as_ref(), 9_000_000, false, "c".repeat(48)).unwrap();
    assert_eq!(next.phase, Phase::Safe);
    assert_eq!(next.failures, 3);
    let mut retried = next;
    retried.phase = Phase::Retry;
    retried.failures = 0;
    assert_eq!(
        next_record(Some(&retried), 9_000_100, false, "d".repeat(48))
            .unwrap()
            .0
            .phase,
        Phase::Starting
    );
}
#[test]
fn clean_healthy_boundary_timeout_forced_and_clock_rollback_are_distinct() {
    for phase in [Phase::Clean, Phase::Ready, Phase::Retry] {
        let (next, _) =
            next_record(Some(&record(phase, 2, 100)), 101, false, "c".repeat(48)).unwrap();
        assert_eq!(next.failures, 0);
    }
    let old = record(Phase::Starting, 2, 100);
    assert_eq!(
        next_record(Some(&old), WINDOW_MS + 100, false, "c".repeat(48))
            .unwrap()
            .0
            .failures,
        3
    );
    assert_eq!(
        next_record(Some(&old), WINDOW_MS + 101, false, "c".repeat(48))
            .unwrap()
            .0
            .failures,
        0
    );
    assert_eq!(
        next_record(Some(&old), 99, false, "c".repeat(48))
            .unwrap_err()
            .code,
        "STARTUP_CLOCK_UNTRUSTED"
    );
    assert_eq!(
        next_record(None, 0, true, "c".repeat(48)).unwrap().1,
        "STARTUP_SAFE_MODE_REQUESTED"
    );
    assert!(next_record(None, u64::MAX, false, "c".repeat(48)).is_err());
}
#[test]
fn malformed_unknown_future_duplicate_and_out_of_bounds_records_reject() {
    let value = serde_json::to_value(record(Phase::Starting, 0, 100)).unwrap();
    for (key, bad) in [
        ("schemaVersion", json!(2)),
        ("failures", json!(4)),
        ("phase", json!("unexpected")),
        ("attemptId", json!("secret")),
        ("startedMs", json!(u64::MAX)),
        ("windowStartMs", json!(101)),
        ("extra", json!("private payload")),
    ] {
        let mut mutated = value.clone();
        mutated[key] = bad;
        assert!(Record::parse(&mutated.to_string()).is_err());
    }
    assert!(Record::parse("{\"schemaVersion\":1,\"schemaVersion\":1}").is_err());
    assert!(Record::parse("null").is_err());
    assert!(Record::parse("{}").is_err());
}
#[test]
fn recovery_admission_excludes_all_state_network_privilege_and_update_actions() {
    for command in [
        "load_state_snapshot",
        "commit_state_patch",
        "recover_state_snapshot",
        "export_state_legacy",
        "runtime_status",
        "diagnostics_snapshot",
        "request_connect",
        "request_disconnect",
        "set_session_authorized",
        "set_system_proxy",
        "repair_runtime_environment",
        "server_ping",
        "ensure_admin_launch",
        "set_launch_on_startup",
        "restart_application",
        "fetch_remote_subscription",
        "write_interface_log",
        "plugin:updater|check",
    ] {
        assert!(!startup_command_allowed(command), "{command}");
    }
    for command in [
        "startup_status",
        "startup_acknowledge_ready",
        "startup_retry_next_launch",
        "startup_exit",
        "request_show",
        "window_minimize",
    ] {
        assert!(startup_command_allowed(command));
    }
}
#[test]
#[cfg(windows)]
fn guard_lease_cannot_be_shared_and_status_contains_no_path_or_state() {
    let path = root();
    let (first, status) = Guard::begin(&path, 100, false).unwrap();
    assert_eq!(
        Guard::begin(&path, 101, false).err().unwrap().code,
        "STARTUP_GUARD_BUSY"
    );
    assert_eq!(status.mode, "normal");
    let text = serde_json::to_string(&status).unwrap();
    assert!(!text.contains(&path.to_string_lossy().to_string()));
    assert!(!text.contains("payload"));
    assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    drop(first);
    assert!(Guard::begin(&path, 102, false).is_ok());
    cleanup(&path);
}
#[test]
#[cfg(windows)]
fn wrong_token_early_ready_and_failed_replace_preserve_original() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
    let path = root();
    let (mut guard, status) = Guard::begin(&path, 100, false).unwrap();
    let original = fs::read(&guard.path).unwrap();
    let id = status.attempt_id.unwrap();
    assert_eq!(
        guard.ready("wrong", READY_AFTER).unwrap_err().code,
        "STARTUP_TOKEN_STALE"
    );
    assert_eq!(
        guard
            .ready(&id, READY_AFTER - Duration::from_millis(1))
            .unwrap_err()
            .code,
        "STARTUP_NOT_STABLE_YET"
    );
    assert_eq!(fs::read(&guard.path).unwrap(), original);
    let blocker = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&guard.path)
        .unwrap();
    assert_eq!(
        guard.ready(&id, READY_AFTER).unwrap_err().code,
        "STARTUP_GUARD_WRITE_FAILED"
    );
    assert_eq!(fs::read(&guard.path).unwrap(), original);
    assert_eq!(guard.record.phase, Phase::Starting);
    drop(blocker);
    guard.ready(&id, READY_AFTER).unwrap();
    guard.ready(&id, READY_AFTER).unwrap();
    assert_eq!(
        Record::parse(&fs::read_to_string(&guard.path).unwrap())
            .unwrap()
            .phase,
        Phase::Ready
    );
    guard.clean().unwrap();
    drop(guard);
    let (_, status) = Guard::begin(&path, 101, false).unwrap();
    assert_eq!(status.failures, 0);
    cleanup(&path);
}
#[test]
#[cfg(windows)]
fn invalid_and_oversized_guard_and_hardlink_do_not_clobber_any_input() {
    let path = root();
    let target = path.join("startup-guard-v1.json");
    for bytes in [b"{invalid".to_vec(), vec![b'x'; 4097]] {
        fs::write(&target, &bytes).unwrap();
        assert!(Guard::begin(&path, 100, false).is_err());
        assert_eq!(fs::read(&target).unwrap(), bytes);
    }
    fs::remove_file(&target).unwrap();
    let original = path.join("synthetic-original");
    fs::write(&original, b"original-owned-test-bytes").unwrap();
    fs::hard_link(&original, &target).unwrap();
    assert!(Guard::begin(&path, 100, false).is_err());
    assert_eq!(fs::read(&original).unwrap(), b"original-owned-test-bytes");
    cleanup(&path);
}
#[test]
#[cfg(windows)]
fn safe_retry_requires_current_attempt_and_never_changes_user_files() {
    let path = root();
    let user = path.join("client-state-v2.dpapi");
    fs::write(&user, b"not-opened-owned-fixture").unwrap();
    let (mut guard, status) = Guard::begin(&path, 100, true).unwrap();
    let id = status.attempt_id.unwrap();
    assert_eq!(status.mode, "safe");
    assert_eq!(
        guard.retry("stale").unwrap_err().code,
        "STARTUP_TOKEN_STALE"
    );
    guard.clean().unwrap();
    assert_eq!(guard.record.phase, Phase::Safe);
    guard.retry(&id).unwrap();
    guard.clean().unwrap();
    assert_eq!(guard.record.phase, Phase::Retry);
    drop(guard);
    let (guard, status) = Guard::begin(&path, 101, false).unwrap();
    assert_eq!(status.mode, "normal");
    assert_eq!(fs::read(&user).unwrap(), b"not-opened-owned-fixture");
    drop(guard);
    cleanup(&path);
}
#[test]
#[cfg(windows)]
fn abrupt_owned_children_leave_attempts_without_any_tauri_or_vpn_process() {
    let path = root();
    for _ in 0..3 {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "startup_guard::tests::abrupt_startup_owned_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VKARMANI_STARTUP_OWNED_FIXTURE", &path);
        assert!(run_command_with_timeout(
            command,
            Duration::from_secs(15),
            "owned abrupt startup fixture"
        )
        .is_err());
        let record =
            Record::parse(&fs::read_to_string(path.join("startup-guard-v1.json")).unwrap())
                .unwrap();
        assert_eq!(record.phase, Phase::Starting);
    }
    let (_, status) = Guard::begin(&path, 200, false).unwrap();
    assert_eq!(status.mode, "safe");
    assert_eq!(status.failures, 3);
    cleanup(&path);
}
#[test]
#[ignore = "owned abrupt child; exercised by parent without launching Tauri or application"]
#[cfg(windows)]
fn abrupt_startup_owned_child() {
    let Some(path) = std::env::var_os("VKARMANI_STARTUP_OWNED_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    assert!(path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("vkarmani-startup-fixture-"));
    assert_eq!(
        path.parent().unwrap().canonicalize().unwrap(),
        std::env::temp_dir().canonicalize().unwrap()
    );
    let (_guard, status) = Guard::begin(&path, 100, false).unwrap();
    assert_eq!(status.mode, "normal");
    std::process::exit(31);
}

#[test]
fn healthy_start_resets_window_before_three_rapid_unconfirmed_restarts() {
    for phase in [Phase::Ready, Phase::Clean, Phase::Retry] {
        let healthy = record(phase, 0, 100);
        let restart_at = WINDOW_MS - 100;
        let mut prior = next_record(Some(&healthy), restart_at, false, "c".repeat(48))
            .unwrap()
            .0;
        for attempt in 1..=3 {
            prior = next_record(
                Some(&prior),
                restart_at + attempt * 100,
                false,
                "d".repeat(48),
            )
            .unwrap()
            .0;
        }
        assert_eq!(
            prior.phase,
            Phase::Safe,
            "Three failures in300ms must not borrow the earlier healthy session window: {phase:?}"
        );
        assert_eq!(prior.failures, 3);
    }
}
