//! Local SCM enumeration/query only. Never starts/stops/reconfigures a service.
use super::*;
use windows_sys::Win32::{
    Foundation::*,
    System::{Services::*, Threading::*},
};

struct ServiceHandle(SC_HANDLE);
impl ServiceHandle {
    fn from_raw(value: SC_HANDLE) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
}
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// Strings returned by SCM point inside its caller-owned aligned buffer.
/// Check range/alignment/NUL before constructing or reading any slice.
fn wide_string(buffer: &[usize], pointer: *const u16, maximum: usize) -> Result<String, String> {
    let start = buffer.as_ptr() as usize;
    let end = start
        .checked_add(std::mem::size_of_val(buffer))
        .ok_or("SERVICE_INVENTORY_INVALID")?;
    let address = pointer as usize;
    if address < start || address >= end || address % 2 != 0 {
        return Err("SERVICE_INVENTORY_INVALID".into());
    }
    let length = ((end - address) / 2).min(maximum + 1);
    let units = unsafe { std::slice::from_raw_parts(pointer, length) };
    let end = units
        .iter()
        .position(|u| *u == 0)
        .ok_or("SERVICE_INVENTORY_INVALID")?;
    let text = String::from_utf16(&units[..end]).map_err(|_| "SERVICE_INVENTORY_INVALID")?;
    if text.chars().any(char::is_control) {
        return Err("SERVICE_INVENTORY_INVALID".into());
    }
    Ok(text)
}
fn executable(command: &str) -> Result<String, String> {
    // Do not infer a future executable from an ambiguous unquoted spaced path,
    // or expand service configuration using this user's environment variables.
    if command.contains('%')
        || (!command.trim_start().starts_with('"')
            && command
                .trim()
                .split_once(char::is_whitespace)
                .is_some_and(|(first, _)| !first.to_ascii_lowercase().ends_with(".exe")))
    {
        return Err("SERVICE_PATH_UNCONFIRMED".into());
    }
    let path = validate_app_identity(command).map_err(|_| "SERVICE_PATH_UNCONFIRMED")?;
    if !path.contains('/') {
        return Err("SERVICE_PATH_UNCONFIRMED".into());
    }
    Ok(path)
}
fn configured_executable(service: &ServiceHandle) -> Result<String, String> {
    // Documented maximum QueryServiceConfig buffer is 8KiB.
    let mut buffer = vec![0usize; 8192 / std::mem::size_of::<usize>()];
    let mut needed = 0;
    if unsafe { QueryServiceConfigW(service.0, buffer.as_mut_ptr().cast(), 8192, &mut needed) } == 0
    {
        return Err("SERVICE_CONFIG_UNAVAILABLE".into());
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    executable(&wide_string(&buffer, config.lpBinaryPathName, 4095)?)
}
fn current_status(service: &ServiceHandle) -> Result<SERVICE_STATUS_PROCESS, String> {
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err("SERVICE_STATUS_UNAVAILABLE".into());
    }
    Ok(status)
}
fn current_executable(pid: u32) -> Result<String, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err("SERVICE_PROCESS_UNAVAILABLE".into());
    }
    struct ProcessHandle(HANDLE);
    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let process = ProcessHandle(process);
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length) } == 0
        || length as usize >= path.len()
    {
        return Err("SERVICE_IMAGE_UNAVAILABLE".into());
    }
    let path =
        String::from_utf16(&path[..length as usize]).map_err(|_| "SERVICE_PATH_UNCONFIRMED")?;
    validate_app_identity(&format!("\"{path}\"")).map_err(|_| "SERVICE_PATH_UNCONFIRMED".into())
}
fn stable_identity(original: &SERVICE_STATUS_PROCESS, current: &SERVICE_STATUS_PROCESS) -> bool {
    original.dwProcessId == current.dwProcessId
        && original.dwCurrentState == current.dwCurrentState
        && original.dwServiceType == current.dwServiceType
}
fn state_label(state: u32) -> &'static str {
    match state {
        SERVICE_RUNNING => "Running",
        SERVICE_STOPPED => "Stopped",
        SERVICE_PAUSED => "Paused",
        SERVICE_START_PENDING => "Start Pending",
        SERVICE_STOP_PENDING => "Stop Pending",
        SERVICE_CONTINUE_PENDING => "Continue Pending",
        SERVICE_PAUSE_PENDING => "Pause Pending",
        _ => "Unknown",
    }
}

pub(super) fn inventory() -> Result<Vec<WindowsServiceInfo>, String> {
    let manager = ServiceHandle::from_raw(unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    })
    .ok_or("SERVICE_INVENTORY_UNAVAILABLE")?;
    let mut services = vec![];
    let mut seen = std::collections::HashSet::new();
    let mut resume = 0;
    let mut bytes = 0usize;
    let started = Instant::now();
    // EnumServicesStatusEx permits at most256KiB/page; no truncation on MORE_DATA.
    for _ in 0..8 {
        let mut buffer = vec![0usize; 262144 / std::mem::size_of::<usize>()];
        let (mut needed, mut returned) = (0, 0);
        let previous_resume = resume;
        let result = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr().cast(),
                262144,
                &mut needed,
                &mut returned,
                &mut resume,
                null(),
            )
        };
        let error = if result == 0 {
            unsafe { GetLastError() }
        } else {
            ERROR_SUCCESS
        };
        if error != ERROR_SUCCESS && error != ERROR_MORE_DATA {
            return Err("SERVICE_INVENTORY_UNAVAILABLE".into());
        }
        let count = returned as usize;
        if count > 2048
            || services.len() + count > 2048
            || count
                > std::mem::size_of_val(buffer.as_slice())
                    / std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>()
        {
            return Err("SERVICE_INVENTORY_LIMIT".into());
        }
        for index in 0..count {
            if started.elapsed() > Duration::from_secs(8) {
                return Err("SERVICE_INVENTORY_DEADLINE".into());
            }
            let item = unsafe {
                std::ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .cast::<ENUM_SERVICE_STATUS_PROCESSW>()
                        .add(index),
                )
            };
            let name = wide_string(&buffer, item.lpServiceName, 256)?;
            let display_name = wide_string(&buffer, item.lpDisplayName, 256)?;
            if name.is_empty() || !seen.insert(name.to_ascii_lowercase()) {
                return Err("SERVICE_INVENTORY_CHANGED".into());
            }
            let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let queried = ServiceHandle::from_raw(unsafe {
                OpenServiceW(
                    manager.0,
                    wide.as_ptr(),
                    SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
                )
            });
            let original = item.ServiceStatusProcess;
            let path = queried
                .as_ref()
                .ok_or_else(|| "SERVICE_QUERY_UNAVAILABLE".to_string())
                .and_then(|handle| {
                    let configured = configured_executable(handle)?;
                    let current = current_status(handle)?;
                    if !stable_identity(&original, &current) {
                        return Err("SERVICE_IDENTITY_CHANGED".into());
                    }
                    if original.dwCurrentState == SERVICE_RUNNING {
                        // A shared host is never a per-service route identity.
                        // Its configured path is metadata only; querying its
                        // protected/system process would grant no new support.
                        if original.dwServiceType != SERVICE_WIN32_OWN_PROCESS {
                            return Ok(configured);
                        }
                        if original.dwProcessId == 0 {
                            return Err("SERVICE_PATH_UNCONFIRMED".into());
                        }
                        let running = current_executable(original.dwProcessId)?;
                        if !configured.eq_ignore_ascii_case(&running)
                            || !stable_identity(&original, &current_status(handle)?)
                        {
                            return Err("SERVICE_IDENTITY_CHANGED".into());
                        }
                        Ok(running)
                    } else if original.dwCurrentState == SERVICE_STOPPED {
                        Ok(configured)
                    } else {
                        Err("SERVICE_TRANSITION_PENDING".into())
                    }
                });
            let (exe_path, reason) = match path {
                Ok(path) => (path, None),
                Err(code) => (String::new(), Some(code)),
            };
            bytes = bytes.saturating_add(name.len() + display_name.len() + exe_path.len() + 128);
            if bytes > 2 * 1024 * 1024 {
                return Err("SERVICE_INVENTORY_LIMIT".into());
            }
            services.push(WindowsServiceInfo {
                name,
                display_name,
                exe_path,
                process_id: original.dwProcessId,
                state: state_label(original.dwCurrentState).into(),
                service_type: if original.dwServiceType == SERVICE_WIN32_SHARE_PROCESS {
                    "Share Process"
                } else if original.dwServiceType == SERVICE_WIN32_OWN_PROCESS {
                    "Own Process"
                } else {
                    "Unknown"
                }
                .into(),
                supported: false,
                reason,
            });
        }
        if error == ERROR_SUCCESS {
            return Ok(services);
        }
        if resume == 0 || (resume == previous_resume && count == 0) {
            return Err("SERVICE_INVENTORY_CHANGED".into());
        }
    }
    Err("SERVICE_INVENTORY_LIMIT".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scm_buffers_reject_external_unaligned_unterminated_and_oversized_strings() {
        let mut buffer = vec![0usize; 8];
        let pointer = buffer.as_mut_ptr().cast::<u16>();
        unsafe {
            pointer.write(b'A' as u16);
            pointer.add(1).write(0);
        }
        assert_eq!(wide_string(&buffer, pointer, 4).unwrap(), "A");
        assert!(wide_string(&buffer, null(), 4).is_err());
        assert!(wide_string(&buffer, (pointer as usize + 1) as *const u16, 4).is_err());
        assert!(wide_string(&buffer, pointer.wrapping_add(100), 4).is_err());
        assert!(wide_string(&buffer, pointer, 0).is_err());
        buffer.fill(usize::MAX);
        assert!(wide_string(&buffer, buffer.as_ptr().cast(), 100).is_err());
    }
    #[test]
    fn configured_paths_do_not_guess_user_environment_unquoted_spaces_or_arguments() {
        assert_eq!(
            executable(r#""C:\Program Files\Svc\service.exe" --private-argument"#).unwrap(),
            "C:/Program Files/Svc/service.exe"
        );
        assert_eq!(
            executable(r"C:\Svc\service.exe --flag").unwrap(),
            "C:/Svc/service.exe"
        );
        for command in [
            r"%SystemRoot%\service.exe",
            r"C:\Program Files\Svc\service.exe",
            r#""C:\Svc\service.exe"suffix"#,
            r"service.exe",
            "C:\\Svc\\service.exe\nsecret",
        ] {
            assert!(executable(command).is_err(), "{command}");
        }
    }
    #[test]
    fn readonly_process_image_query_handles_normal_kernel_and_inaccessible_identities_without_guessing(
    ) {
        let own = current_executable(std::process::id()).unwrap();
        assert!(own.contains('/') && own.to_ascii_lowercase().ends_with(".exe"));
        assert!(current_executable(0).is_err());
        // SYSTEM kernel PID4 is not a normal executable identity. Xray has a
        // separate :System special case, never an application .exe fallback.
        assert!(current_executable(4).is_err());
    }
    #[test]
    fn service_identity_drift_and_query_handles_are_fail_closed() {
        assert!(ServiceHandle::from_raw(null_mut()).is_none());
        let mut first: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        first.dwProcessId = 17;
        first.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        first.dwCurrentState = SERVICE_RUNNING;
        assert!(stable_identity(&first, &first));
        let mut changed = first;
        changed.dwProcessId += 1;
        assert!(!stable_identity(&first, &changed));
        changed = first;
        changed.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
        assert!(!stable_identity(&first, &changed));
        changed = first;
        changed.dwCurrentState = SERVICE_STOPPED;
        assert!(!stable_identity(&first, &changed));
    }
}
