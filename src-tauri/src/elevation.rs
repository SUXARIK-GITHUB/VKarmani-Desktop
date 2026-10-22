//! Same-image RunAs handover. A pending elevated child does not construct Tauri,
//! touch AppData or acquire the single-instance lock until the exact parent exits.
use super::*;
const PREFIX: &str = "--vkarmani-elevate-handoff=";
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ElevationError {
    pub(crate) code: &'static str,
    category: &'static str,
    retryable: bool,
}
fn failure(code: &'static str) -> ElevationError {
    ElevationError {
        code,
        category: "lifecycle",
        retryable: true,
    }
}

#[derive(Debug, PartialEq)]
struct ParentSpec {
    pid: u32,
    created: u64,
    nonce: String,
}
fn parse(args: &[String]) -> Result<Option<ParentSpec>, ElevationError> {
    let values = args
        .iter()
        .skip(1)
        .filter(|a| a.starts_with("--vkarmani-elevate-handoff"))
        .take(2)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(failure("ELEVATION_ARGS_INVALID"));
    }
    if values[0].len() > 128 {
        return Err(failure("ELEVATION_ARGS_INVALID"));
    }
    let parts = values[0]
        .strip_prefix(PREFIX)
        .ok_or_else(|| failure("ELEVATION_ARGS_INVALID"))?
        .split(':')
        .collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0].is_empty()
        || parts[0].len() > 10
        || parts[1].is_empty()
        || parts[1].len() > 20
        || !parts[0].bytes().all(|b| b.is_ascii_digit())
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
        || parts[2].len() != 48
        || !parts[2].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(failure("ELEVATION_ARGS_INVALID"));
    }
    let pid = parts[0]
        .parse()
        .map_err(|_| failure("ELEVATION_ARGS_INVALID"))?;
    let created = parts[1]
        .parse()
        .map_err(|_| failure("ELEVATION_ARGS_INVALID"))?;
    if pid == 0 || created == 0 {
        return Err(failure("ELEVATION_ARGS_INVALID"));
    }
    Ok(Some(ParentSpec {
        pid,
        created,
        nonce: parts[2].into(),
    }))
}
#[cfg(any(test, all(windows, not(debug_assertions))))]
fn quote_arg(value: &str) -> Result<String, ElevationError> {
    if value.contains('\0') {
        return Err(failure("ELEVATION_ARGS_INVALID"));
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        out.push_str(&"\\".repeat(if ch == '"' { slashes * 2 + 1 } else { slashes }));
        out.push(ch);
        slashes = 0;
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    Ok(out)
}
fn filtered(args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    args.into_iter()
        .filter(|a| {
            !a.to_string_lossy()
                .starts_with("--vkarmani-elevate-handoff")
        })
        .collect()
}

#[cfg(any(test, all(windows, not(debug_assertions))))]
trait Backend {
    fn request(&mut self) -> Result<bool, ElevationError>;
    fn ready(&mut self) -> Result<(), ElevationError>;
    fn cleanup(&mut self) -> Result<(), ElevationError>;
    fn commit(&mut self) -> Result<(), ElevationError>;
    fn exit(&mut self);
}
#[cfg(any(test, all(windows, not(debug_assertions))))]
fn transaction(backend: &mut impl Backend) -> Result<bool, ElevationError> {
    if !backend.request()? {
        return Ok(false);
    }
    backend.ready()?;
    backend.cleanup()?;
    backend.commit()?;
    backend.exit();
    Ok(true)
}

pub(crate) fn startup_environment() -> Result<tauri::Env, ElevationError> {
    let mut env = tauri::Env::default();
    let args = env
        .args_os
        .iter()
        .map(|a| {
            a.to_str()
                .map(str::to_string)
                .ok_or_else(|| failure("ELEVATION_ARGS_INVALID"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(spec) = parse(&args)? {
        #[cfg(all(windows, not(debug_assertions)))]
        native::wait_for_parent(&spec)?;
        #[cfg(not(all(windows, not(debug_assertions))))]
        {
            let _ = spec;
            return Err(failure("ELEVATION_BUILD_UNSUPPORTED"));
        }
    }
    // Official Tauri restart uses Env.args_os. Never replay an expired parent
    // token after a successful elevation, normal restart or updater relaunch.
    env.args_os = filtered(env.args_os);
    Ok(env)
}

pub(crate) fn relaunch(app: &AppHandle) -> Result<bool, ElevationError> {
    #[cfg(all(windows, not(debug_assertions)))]
    {
        if is_process_elevated().map_err(|_| failure("ELEVATION_TOKEN_UNAVAILABLE"))? {
            return Ok(false);
        }
        transaction(&mut native::WindowsBackend::new(app.clone()))
    }
    #[cfg(not(all(windows, not(debug_assertions))))]
    {
        let _ = app;
        Ok(false)
    }
}

#[cfg(all(windows, any(test, not(debug_assertions))))]
fn handoff_wait_handles(
    cancel: windows_sys::Win32::Foundation::HANDLE,
    go: windows_sys::Win32::Foundation::HANDLE,
    parent: windows_sys::Win32::Foundation::HANDLE,
) -> [windows_sys::Win32::Foundation::HANDLE; 3] {
    [cancel, go, parent]
}

#[cfg(all(windows, not(debug_assertions)))]
mod native {
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, EqualSid, SECURITY_ATTRIBUTES},
        System::{Com::*, Threading::*},
        UI::Shell::*,
    };
    struct Handle(HANDLE);
    impl Handle {
        fn owned(value: HANDLE) -> Result<Self, ElevationError> {
            if value.is_null() || value == INVALID_HANDLE_VALUE {
                Err(failure("ELEVATION_HANDLE_UNAVAILABLE"))
            } else {
                Ok(Self(value))
            }
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Allocation(*mut std::ffi::c_void);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                crate::LocalFree(self.0);
            }
        }
    }
    struct Com;
    impl Com {
        fn initialize() -> Result<Self, ElevationError> {
            if unsafe {
                CoInitializeEx(
                    null(),
                    (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
                )
            } < 0
            {
                return Err(failure("ELEVATION_COM_UNAVAILABLE"));
            }
            Ok(Self)
        }
    }
    impl Drop for Com {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
    fn wide(text: &str) -> Result<Vec<u16>, ElevationError> {
        if text.contains('\0') {
            return Err(failure("ELEVATION_ARGS_INVALID"));
        }
        Ok(text.encode_utf16().chain(Some(0)).collect())
    }
    fn start_time(handle: HANDLE) -> Result<u64, ElevationError> {
        let (mut created, mut exited, mut kernel, mut user): (
            FILETIME,
            FILETIME,
            FILETIME,
            FILETIME,
        ) = unsafe { std::mem::zeroed() };
        if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(failure("ELEVATION_IDENTITY_UNAVAILABLE"));
        }
        Ok(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
    }
    fn image(handle: HANDLE) -> Result<PathBuf, ElevationError> {
        let mut text = vec![0u16; 32768];
        let mut len = text.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle, 0, text.as_mut_ptr(), &mut len) } == 0
            || len as usize >= text.len()
        {
            return Err(failure("ELEVATION_IDENTITY_UNAVAILABLE"));
        }
        fs::canonicalize(PathBuf::from(std::ffi::OsString::from_wide(
            &text[..len as usize],
        )))
        .map_err(|_| failure("ELEVATION_IDENTITY_UNAVAILABLE"))
    }
    fn same_user(left: HANDLE, right: HANDLE) -> Result<bool, ElevationError> {
        let a = crate::process_inventory::owner_sid(left)
            .ok_or_else(|| failure("ELEVATION_IDENTITY_UNAVAILABLE"))?;
        let b = crate::process_inventory::owner_sid(right)
            .ok_or_else(|| failure("ELEVATION_IDENTITY_UNAVAILABLE"))?;
        Ok(unsafe { EqualSid(a.as_ptr().cast_mut().cast(), b.as_ptr().cast_mut().cast()) } != 0)
    }
    fn descriptor() -> Result<Allocation, ElevationError> {
        let sid = crate::process_inventory::owner_sid(unsafe { GetCurrentProcess() })
            .ok_or_else(|| failure("ELEVATION_IDENTITY_UNAVAILABLE"))?;
        let mut sid_text = null_mut();
        if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut sid_text) } == 0 {
            return Err(failure("ELEVATION_ACL_UNAVAILABLE"));
        }
        let _sid_owner = Allocation(sid_text.cast());
        let mut len = 0;
        while len < 256 && unsafe { *sid_text.add(len) } != 0 {
            len += 1;
        }
        if len == 256 {
            return Err(failure("ELEVATION_ACL_UNAVAILABLE"));
        }
        let sid = String::from_utf16(unsafe { slice::from_raw_parts(sid_text, len) })
            .map_err(|_| failure("ELEVATION_ACL_UNAVAILABLE"))?;
        let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})"))?;
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(failure("ELEVATION_ACL_UNAVAILABLE"));
        }
        Ok(Allocation(descriptor))
    }
    struct Events {
        ready: Handle,
        go: Handle,
        cancel: Handle,
    }
    impl Events {
        fn open(nonce: &str, create: bool) -> Result<Self, ElevationError> {
            let descriptor = if create { Some(descriptor()?) } else { None };
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.as_ref().map_or(null_mut(), |d| d.0),
                bInheritHandle: 0,
            };
            let event = |suffix: &str| -> Result<Handle, ElevationError> {
                let name = wide(&format!("Local\\VKarmaniElevate-{nonce}-{suffix}"))?;
                let raw = unsafe {
                    if create {
                        CreateEventW(&attributes, 1, 0, name.as_ptr())
                    } else {
                        OpenEventW(
                            SYNCHRONIZATION_SYNCHRONIZE | EVENT_MODIFY_STATE,
                            0,
                            name.as_ptr(),
                        )
                    }
                };
                let code = unsafe { GetLastError() };
                let handle = Handle::owned(raw)?;
                if create && code == ERROR_ALREADY_EXISTS {
                    return Err(failure("ELEVATION_EVENT_COLLISION"));
                }
                Ok(handle)
            };
            Ok(Self {
                ready: event("ready")?,
                go: event("go")?,
                cancel: event("cancel")?,
            })
        }
    }
    pub(super) fn wait_for_parent(spec: &ParentSpec) -> Result<(), ElevationError> {
        if spec.pid == std::process::id()
            || !is_process_elevated().map_err(|_| failure("ELEVATION_TOKEN_UNAVAILABLE"))?
        {
            return Err(failure("ELEVATION_NOT_ELEVATED"));
        }
        let parent = Handle::owned(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                spec.pid,
            )
        })?;
        let current = unsafe { GetCurrentProcess() };
        if start_time(parent.0)? != spec.created
            || !same_user(parent.0, current)?
            || image(parent.0)? != image(current)?
            || unsafe { WaitForSingleObject(parent.0, 0) } != WAIT_TIMEOUT
        {
            return Err(failure("ELEVATION_PARENT_MISMATCH"));
        }
        let events = Events::open(&spec.nonce, false)?;
        if unsafe { SetEvent(events.ready.0) } == 0 {
            return Err(failure("ELEVATION_EVENT_FAILED"));
        }
        // If the parent commits and exits before we are scheduled, both go and
        // parent are signalled. Cancellation wins, then the committed grant;
        // parent death alone must never authorize constructing the application.
        let waiting = handoff_wait_handles(events.cancel.0, events.go.0, parent.0);
        if unsafe { WaitForMultipleObjects(3, waiting.as_ptr(), 0, 30000) } != WAIT_OBJECT_0 + 1 {
            return Err(failure("ELEVATION_NOT_COMMITTED"));
        }
        let waiting = [events.cancel.0, parent.0];
        if unsafe { WaitForMultipleObjects(2, waiting.as_ptr(), 0, 20000) } != WAIT_OBJECT_0 + 1 {
            return Err(failure("ELEVATION_PARENT_EXIT_UNCONFIRMED"));
        }
        Ok(())
    }
    struct Pending {
        events: Events,
        child: Handle,
        committed: bool,
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            if !self.committed {
                unsafe {
                    SetEvent(self.events.cancel.0);
                }
            }
        }
    }
    pub(super) struct WindowsBackend {
        app: AppHandle,
        pending: Option<Pending>,
    }
    impl WindowsBackend {
        pub(super) fn new(app: AppHandle) -> Self {
            Self { app, pending: None }
        }
    }
    impl Backend for WindowsBackend {
        fn request(&mut self) -> Result<bool, ElevationError> {
            let nonce = crate::durable_state::random_state_id()
                .map_err(|_| failure("ELEVATION_IDENTITY_UNAVAILABLE"))?;
            let events = Events::open(&nonce, true)?;
            let mut args = self
                .app
                .env()
                .args_os
                .into_iter()
                .skip(1)
                .map(|a| {
                    a.into_string()
                        .map_err(|_| failure("ELEVATION_ARGS_INVALID"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            args.push(format!(
                "{PREFIX}{}:{}:{nonce}",
                std::process::id(),
                start_time(unsafe { GetCurrentProcess() })?
            ));
            let parameters = args
                .iter()
                .map(|a| quote_arg(a))
                .collect::<Result<Vec<_>, _>>()?
                .join(" ");
            if parameters.encode_utf16().count() > 32760 {
                return Err(failure("ELEVATION_ARGS_INVALID"));
            }
            let path =
                std::env::current_exe().map_err(|_| failure("ELEVATION_IDENTITY_UNAVAILABLE"))?;
            let path = wide(
                path.to_str()
                    .ok_or_else(|| failure("ELEVATION_ARGS_INVALID"))?,
            )?;
            let parameters = wide(&parameters)?;
            let verb = wide("runas")?;
            let _com = Com::initialize()?;
            let mut shell: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
            shell.cbSize = std::mem::size_of_val(&shell) as u32;
            shell.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
            shell.lpVerb = verb.as_ptr();
            shell.lpFile = path.as_ptr();
            shell.lpParameters = parameters.as_ptr();
            shell.nShow = 1;
            if unsafe { ShellExecuteExW(&mut shell) } == 0 {
                if unsafe { GetLastError() } == ERROR_CANCELLED {
                    return Ok(false);
                }
                return Err(failure("ELEVATION_LAUNCH_FAILED"));
            }
            self.pending = Some(Pending {
                events,
                child: Handle::owned(shell.hProcess)?,
                committed: false,
            });
            Ok(true)
        }
        fn ready(&mut self) -> Result<(), ElevationError> {
            let p = self
                .pending
                .as_ref()
                .ok_or_else(|| failure("ELEVATION_CHILD_UNAVAILABLE"))?;
            let handles = [p.events.ready.0, p.child.0];
            if unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 10000) } != WAIT_OBJECT_0
                || unsafe { WaitForSingleObject(p.child.0, 0) } != WAIT_TIMEOUT
            {
                return Err(failure("ELEVATION_CHILD_UNAVAILABLE"));
            }
            Ok(())
        }
        fn cleanup(&mut self) -> Result<(), ElevationError> {
            cleanup_application(&self.app, "state_handoff_elevate")
                .map_err(|_| failure("ELEVATION_CLEANUP_UNCONFIRMED"))
        }
        fn commit(&mut self) -> Result<(), ElevationError> {
            let p = self
                .pending
                .as_mut()
                .ok_or_else(|| failure("ELEVATION_CHILD_UNAVAILABLE"))?;
            if unsafe { WaitForSingleObject(p.child.0, 0) } != WAIT_TIMEOUT
                || unsafe { SetEvent(p.events.go.0) } == 0
            {
                return Err(failure("ELEVATION_EVENT_FAILED"));
            }
            p.committed = true;
            Ok(())
        }
        fn exit(&mut self) {
            self.app
                .state::<AppState>()
                .exit_approved
                .store(true, std::sync::atomic::Ordering::Release);
            self.app.exit(0);
        }
    }
}

#[cfg(test)]
mod tests;
