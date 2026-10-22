//! Best-effort Rust panic receipts. SEH/access violations/heap corruption and
//! abrupt process termination are NOT intercepted or diagnosed by this hook.
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Once, OnceLock,
};

#[derive(Clone, Copy)]
pub(crate) enum CrashPhase {
    Builder = 0,
    StartupRecovery = 1,
    Tray = 2,
    Updater = 3,
    Runtime = 4,
}
static PHASE: AtomicU8 = AtomicU8::new(0);
static SINK: OnceLock<PathBuf> = OnceLock::new();
static WRITING: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicU8 = AtomicU8::new(0);

pub(crate) fn crash_phase(phase: CrashPhase) {
    PHASE.store(phase as u8, Ordering::Relaxed);
}
pub(crate) fn configure_crash_sink(app: &AppHandle) {
    if let Ok(root) = interface_logs_dir(app) {
        let _ = SINK.set(root.join("native-crash-last.json"));
    }
}
fn safe_frames(backtrace: &str) -> Vec<String> {
    backtrace
        .lines()
        .take(256)
        .filter_map(|line| {
            let (_, name) = line.trim().split_once(": ")?;
            if !name.starts_with("vkarmani_desktop_lib::") {
                return None;
            }
            Some(
                name.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || "_:<>".contains(*c))
                    .take(160)
                    .collect(),
            )
        })
        .take(12)
        .collect()
}
fn receipt(phase: u8, location: Option<(&str, u32, u32)>, backtrace: &str) -> Value {
    let phase = match phase {
        0 => "builder",
        1 => "startup_owned_recovery",
        2 => "tray_setup",
        3 => "updater_setup",
        _ => "runtime",
    };
    // Source filename and panic payload may contain sensitive text. Numeric
    // location plus allowlisted compiled symbols identify the exact build site.
    json!({
        "schemaVersion":1,"appVersion":env!("CARGO_PKG_VERSION"),"source":"rust",
        "code":"RUST_PANIC","phase":phase,
        "timestampUnixMs":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().to_string(),
        "location":location.map(|(_,line,column)|json!({"line":line,"column":column})),
        "stack":safe_frames(backtrace)
    })
}
fn write_receipt(path: &Path, value: &Value) -> std::io::Result<()> {
    atomic_write_state_text_with_limit(path, &value.to_string(), 4096)
}
pub(crate) fn install_crash_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            if COUNT
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < 8).then_some(n + 1)
                })
                .is_err()
                || WRITING
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
            {
                return;
            }
            let backtrace = std::backtrace::Backtrace::force_capture().to_string();
            let value = receipt(
                PHASE.load(Ordering::Relaxed),
                info.location().map(|v| (v.file(), v.line(), v.column())),
                &backtrace,
            );
            // Do not chain the default hook: it writes unredacted panic payloads.
            eprintln!("CRASH_RECEIPT {value}");
            if let Some(path) = SINK.get() {
                let _ = write_receipt(path, &value);
            }
            WRITING.store(false, Ordering::Release);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_locations_and_bounded_compiled_symbols_exclude_paths_and_payloads() {
        let trace = format!("0: external::secret\n1: vkarmani_desktop_lib::operation::connect\n at C:\\private\\secret.rs:10:1\n2: vkarmani_desktop_lib::safe (password=secret)\n{}", "3: vkarmani_desktop_lib::safe\n".repeat(1000));
        let value = receipt(1, Some(("private-user-path", 10, 2)), &trace);
        assert_eq!(value["code"], "RUST_PANIC");
        assert_eq!(value["phase"], "startup_owned_recovery");
        assert_eq!(value["location"], json!({"line":10,"column":2}));
        assert_eq!(value["stack"].as_array().unwrap().len(), 12);
        assert_eq!(value["appVersion"], env!("CARGO_PKG_VERSION"));
        for secret in ["secret", "private", "password", "external"] {
            assert!(!value.to_string().contains(secret));
        }
        assert!(value.to_string().len() < 4096);
    }

    #[test]
    fn builder_panic_before_sink_is_redacted_on_stderr_without_app_state() {
        let _guard = HELPER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!(
            "vkarmani-native-crash-{}-{}",
            std::process::id(),
            crate::durable_state::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "crash_receipts::tests::panic_hook_owned_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VKARMANI_OWNED_CRASH_FIXTURE", &root)
            .env("VKARMANI_OWNED_CRASH_BEFORE_SINK", "1");
        // The generic command wrapper intentionally redacts opaque JSON tokens.
        // Inspect only this synthetic child's bounded raw stderr, retaining its
        // exact job/handle so even an assertion/timeout cannot leave it alive.
        hide_child_console(&mut child);
        let mut child = OwnedXrayProcess::attach(
            child
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
        .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut output = String::new();
            let result = stderr.take(8192).read_to_string(&mut output);
            let _ = tx.send(result.map(|_| output));
        });
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "owned crash fixture deadline");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(31));
        drop(child);
        let output = rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        let raw = output
            .lines()
            .find_map(|line| line.strip_prefix("CRASH_RECEIPT "))
            .unwrap();
        let receipt: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(receipt["phase"], "builder");
        assert_eq!(receipt["code"], "RUST_PANIC");
        assert!(!output.contains("sensitive-test-payload"));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn isolated_process_runs_actual_panic_hook_without_default_secret_payload_or_gui() {
        let _guard = HELPER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "vkarmani-native-crash-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "crash_receipts::tests::panic_hook_owned_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VKARMANI_OWNED_CRASH_FIXTURE", &root);
        let result =
            run_command_with_timeout(child, Duration::from_secs(15), "owned crash hook fixture");
        assert!(result.is_ok(), "owned child: {result:?}");
        let value: Value =
            serde_json::from_slice(&fs::read(root.join("native-crash-last.json")).unwrap())
                .unwrap();
        assert_eq!(value["code"], "RUST_PANIC");
        assert_eq!(value["phase"], "runtime");
        assert!(!value.to_string().contains("sensitive-test-payload"));
        assert!(fs::read_dir(&root).unwrap().count() == 1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    #[ignore = "owned child entry exercised by isolated_process_runs_actual_panic_hook_without_default_secret_payload_or_gui"]
    fn panic_hook_owned_child() {
        let Some(root) = std::env::var_os("VKARMANI_OWNED_CRASH_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("vkarmani-native-crash-"));
        assert_eq!(
            root.parent().unwrap().canonicalize().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        let early = std::env::var("VKARMANI_OWNED_CRASH_BEFORE_SINK").as_deref() == Ok("1");
        if !early {
            SINK.set(root.join("native-crash-last.json")).unwrap();
        }
        crash_phase(if early {
            CrashPhase::Builder
        } else {
            CrashPhase::Runtime
        });
        install_crash_hook();
        assert!(std::thread::spawn(|| panic!("sensitive-test-payload"))
            .join()
            .is_err());
        if early {
            std::process::exit(31);
        }
    }
}
