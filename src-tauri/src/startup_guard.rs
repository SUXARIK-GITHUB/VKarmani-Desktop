//! Startup-loop detection is separate from user state. No credential/state load,
//! runtime recovery or network action is allowed by this module.
use super::*;

const LIMIT: u8 = 3;
const WINDOW_MS: u64 = 600_000;
const READY_AFTER: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Starting,
    Ready,
    Clean,
    Safe,
    Retry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema_version: u8,
    attempt_id: String,
    failures: u8,
    window_start_ms: u64,
    started_ms: u64,
    phase: Phase,
}
impl Record {
    fn parse(text: &str) -> Result<Self, StartupError> {
        let value: Self = serde_json::from_str(text).map_err(|_| error("STARTUP_GUARD_INVALID"))?;
        if value.schema_version != 1
            || value.failures > LIMIT
            || value.attempt_id.len() != 48
            || !value.attempt_id.bytes().all(|b| b.is_ascii_hexdigit())
            || value.window_start_ms > value.started_ms
            || value.started_ms > 8_640_000_000_000_000
        {
            return Err(error("STARTUP_GUARD_INVALID"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartupError {
    pub(crate) code: &'static str,
    category: &'static str,
    retryable: bool,
}
fn error(code: &'static str) -> StartupError {
    StartupError {
        code,
        category: "startup",
        retryable: false,
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartupStatus {
    schema_version: u8,
    mode: &'static str,
    code: &'static str,
    app_version: &'static str,
    failures: u8,
    attempt_id: Option<String>,
    retry_allowed: bool,
    ready_after_ms: u64,
}
impl StartupStatus {
    fn safe(code: &'static str) -> Self {
        Self {
            schema_version: 1,
            mode: "safe",
            code,
            app_version: env!("CARGO_PKG_VERSION"),
            failures: 0,
            attempt_id: None,
            retry_allowed: false,
            ready_after_ms: 0,
        }
    }
}

struct StartupLease {
    _file: File,
    _parents: Vec<File>,
}
impl StartupLease {
    #[cfg(windows)]
    fn acquire(root: &Path) -> Result<Self, StartupError> {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::{Storage::FileSystem::*, System::IO::OVERLAPPED};
        let parents =
            state_directory_guards(root, true).map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root.join("startup.session.lock"))
            .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
        check_state_file(&file).map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
        let mut overlap: OVERLAPPED = unsafe { std::mem::zeroed() };
        if unsafe {
            LockFileEx(
                file.as_raw_handle().cast(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlap,
            )
        } == 0
        {
            return Err(error("STARTUP_GUARD_BUSY"));
        }
        // Retaining the exact file and directory handles owns this lease until
        // process exit; closing the File releases the lock, including on crash.
        Ok(Self {
            _file: file,
            _parents: parents,
        })
    }
    #[cfg(not(windows))]
    fn acquire(_root: &Path) -> Result<Self, StartupError> {
        Err(error("STARTUP_PLATFORM_UNSUPPORTED"))
    }
}

struct Guard {
    _lease: StartupLease,
    path: PathBuf,
    record: Record,
    started: Instant,
}
impl Guard {
    fn begin(root: &Path, now: u64, forced: bool) -> Result<(Self, StartupStatus), StartupError> {
        let lease = StartupLease::acquire(root)?;
        let path = root.join("startup-guard-v1.json");
        let prior = read_state_file(&path, 4096)
            .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?
            .map(|text| Record::parse(&text))
            .transpose()?;
        let id = crate::durable_state::random_state_id()
            .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
        let (record, code) = next_record(prior.as_ref(), now, forced, id)?;
        atomic_write_state_text_with_limit(
            &path,
            &serde_json::to_string(&record).map_err(|_| error("STARTUP_GUARD_INVALID"))?,
            4096,
        )
        .map_err(|_| error("STARTUP_GUARD_WRITE_FAILED"))?;
        let safe = record.phase == Phase::Safe;
        let status = StartupStatus {
            schema_version: 1,
            mode: if safe { "safe" } else { "normal" },
            code,
            app_version: env!("CARGO_PKG_VERSION"),
            failures: record.failures,
            attempt_id: Some(record.attempt_id.clone()),
            retry_allowed: safe,
            ready_after_ms: READY_AFTER.as_millis() as u64,
        };
        Ok((
            Self {
                _lease: lease,
                path,
                record,
                started: Instant::now(),
            },
            status,
        ))
    }
    fn publish(&mut self, next: Record) -> Result<(), StartupError> {
        atomic_write_state_text_with_limit(
            &self.path,
            &serde_json::to_string(&next).map_err(|_| error("STARTUP_GUARD_INVALID"))?,
            4096,
        )
        .map_err(|_| error("STARTUP_GUARD_WRITE_FAILED"))?;
        self.record = next;
        Ok(())
    }
    fn ready(&mut self, id: &str, elapsed: Duration) -> Result<(), StartupError> {
        if self.record.attempt_id != id {
            return Err(error("STARTUP_TOKEN_STALE"));
        }
        if self.record.phase == Phase::Ready {
            return Ok(());
        }
        if self.record.phase != Phase::Starting {
            return Err(error("STARTUP_SAFE_MODE_REQUIRED"));
        }
        if elapsed < READY_AFTER {
            return Err(error("STARTUP_NOT_STABLE_YET"));
        }
        let mut next = self.record.clone();
        next.phase = Phase::Ready;
        next.failures = 0;
        self.publish(next)
    }
    fn retry(&mut self, id: &str) -> Result<(), StartupError> {
        if self.record.attempt_id != id {
            return Err(error("STARTUP_TOKEN_STALE"));
        }
        if !matches!(self.record.phase, Phase::Safe | Phase::Retry) {
            return Err(error("STARTUP_SAFE_MODE_REQUIRED"));
        }
        let mut next = self.record.clone();
        next.phase = Phase::Retry;
        next.failures = 0;
        self.publish(next)
    }
    fn clean(&mut self) -> Result<(), StartupError> {
        if matches!(self.record.phase, Phase::Safe | Phase::Retry | Phase::Clean) {
            return Ok(());
        }
        let mut next = self.record.clone();
        next.phase = Phase::Clean;
        next.failures = 0;
        self.publish(next)
    }
}

fn next_record(
    prior: Option<&Record>,
    now: u64,
    forced: bool,
    id: String,
) -> Result<(Record, &'static str), StartupError> {
    if now > 8_640_000_000_000_000 || prior.is_some_and(|p| now < p.started_ms) {
        return Err(error("STARTUP_CLOCK_UNTRUSTED"));
    }
    let in_window = prior.is_some_and(|p| now.saturating_sub(p.window_start_ms) <= WINDOW_MS);
    let failures = prior.map_or(0, |p| {
        if p.phase == Phase::Safe {
            p.failures
        } else if p.phase == Phase::Starting && in_window {
            p.failures.saturating_add(1).min(LIMIT)
        } else {
            0
        }
    });
    let latched = prior.is_some_and(|p| p.phase == Phase::Safe);
    let safe = forced || latched || failures >= LIMIT;
    let code = if forced {
        "STARTUP_SAFE_MODE_REQUESTED"
    } else if safe {
        "STARTUP_CRASH_LOOP"
    } else {
        "STARTUP_NORMAL"
    };
    let window_start_ms = prior
        // A healthy/clean/explicit-retry boundary starts a new failure chain.
        // Reusing its older window can erase three rapid new crashes at expiry.
        .filter(|p| in_window && p.phase == Phase::Starting)
        .map_or(now, |p| p.window_start_ms);
    Ok((
        Record {
            schema_version: 1,
            attempt_id: id,
            failures,
            window_start_ms,
            started_ms: now,
            phase: if safe { Phase::Safe } else { Phase::Starting },
        },
        code,
    ))
}

pub(crate) struct StartupSupervisor {
    guard: Option<Guard>,
    status: StartupStatus,
    admitted: bool,
}
impl Default for StartupSupervisor {
    fn default() -> Self {
        Self {
            guard: None,
            status: StartupStatus::safe("STARTUP_NOT_READY"),
            admitted: false,
        }
    }
}
impl StartupSupervisor {
    fn commands_blocked(&self) -> bool {
        self.is_safe() || !self.admitted
    }
    fn admit(&mut self, attempt_id: &str) -> Result<(), StartupError> {
        if self.is_safe() {
            return Err(error("STARTUP_SAFE_MODE_REQUIRED"));
        }
        if self
            .guard
            .as_ref()
            .map_or(true, |g| g.record.attempt_id != attempt_id)
        {
            return Err(error("STARTUP_TOKEN_STALE"));
        }
        self.admitted = true;
        Ok(())
    }
    pub(crate) fn initialize(app: &AppHandle) -> Self {
        let result = app
            .path()
            .app_local_data_dir()
            .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))
            .and_then(|root| {
                Guard::begin(
                    &root,
                    unix_timestamp_seconds().saturating_mul(1000),
                    std::env::args().skip(1).any(|arg| arg == "--safe-mode"),
                )
            });
        match result {
            Ok((guard, status)) => Self {
                guard: Some(guard),
                status,
                admitted: false,
            },
            Err(failure) => Self {
                guard: None,
                status: StartupStatus::safe(failure.code),
                admitted: false,
            },
        }
    }
    pub(crate) fn is_safe(&self) -> bool {
        self.status.mode != "normal"
    }
    pub(crate) fn clean_exit(&mut self) {
        if let Some(guard) = self.guard.as_mut() {
            let _ = guard.clean();
        }
    }
}
pub(crate) fn startup_is_safe(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .startup
        .lock()
        .map(|s| s.is_safe())
        .unwrap_or(true)
}
pub(crate) fn startup_command_allowed(command: &str) -> bool {
    matches!(
        command,
        "startup_status"
            | "startup_admit_app"
            | "startup_acknowledge_ready"
            | "startup_retry_next_launch"
            | "startup_exit"
            | "request_show"
            | "window_minimize"
            | "window_toggle_maximize"
    )
}
pub(crate) fn startup_commands_blocked(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .startup
        .lock()
        .map(|s| s.commands_blocked())
        .unwrap_or(true)
}

#[tauri::command]
pub(crate) fn startup_admit_app(app: AppHandle, attempt_id: String) -> Result<(), StartupError> {
    let state = app.state::<AppState>();
    let mut supervisor = state
        .startup
        .lock()
        .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
    supervisor.admit(&attempt_id)
}
pub(crate) fn startup_note_clean_exit(app: &AppHandle) {
    if let Ok(mut supervisor) = app.state::<AppState>().startup.lock() {
        supervisor.clean_exit();
    }
}

#[tauri::command]
pub(crate) fn startup_status(app: AppHandle) -> Result<StartupStatus, StartupError> {
    app.state::<AppState>()
        .startup
        .lock()
        .map(|s| s.status.clone())
        .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))
}
#[tauri::command]
pub(crate) fn startup_acknowledge_ready(
    app: AppHandle,
    attempt_id: String,
) -> Result<(), StartupError> {
    let state = app.state::<AppState>();
    let mut supervisor = state
        .startup
        .lock()
        .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
    if !supervisor.admitted {
        return Err(error("STARTUP_NOT_READY"));
    }
    let guard = supervisor
        .guard
        .as_mut()
        .ok_or_else(|| error("STARTUP_GUARD_UNAVAILABLE"))?;
    guard.ready(&attempt_id, guard.started.elapsed())
}
#[tauri::command]
pub(crate) fn startup_retry_next_launch(
    app: AppHandle,
    attempt_id: String,
) -> Result<(), StartupError> {
    let state = app.state::<AppState>();
    let mut supervisor = state
        .startup
        .lock()
        .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?;
    if !supervisor.is_safe() {
        return Err(error("STARTUP_SAFE_MODE_REQUIRED"));
    }
    supervisor
        .guard
        .as_mut()
        .ok_or_else(|| error("STARTUP_GUARD_UNAVAILABLE"))?
        .retry(&attempt_id)
}
#[tauri::command]
pub(crate) fn startup_exit(app: AppHandle) -> Result<(), StartupError> {
    if !startup_commands_blocked(&app) {
        return Err(error("STARTUP_SAFE_MODE_REQUIRED"));
    }
    let state = app.state::<AppState>();
    if state
        .runtime
        .lock()
        .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?
        .is_some()
        || state
            .starting_runtime
            .lock()
            .map_err(|_| error("STARTUP_GUARD_UNAVAILABLE"))?
            .is_some()
    {
        return Err(error("STARTUP_RUNTIME_PRESENT"));
    }
    app.exit(0);
    Ok(())
}

#[cfg(test)]
mod tests;
