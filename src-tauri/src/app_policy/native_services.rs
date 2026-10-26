//! Local read-only SCM inventory. No shell/WMI or service control permissions.
use super::{validate_app_identity, WindowsServiceInfo};
use std::{mem::size_of, ptr::null};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_MORE_DATA},
    System::Services::*,
};

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn wide_in_buffer(buffer: &[usize], pointer: *const u16, limit: usize) -> Result<String, String> {
    let base = buffer.as_ptr() as usize;
    let end = base + std::mem::size_of_val(buffer);
    let address = pointer as usize;
    if address < base || address >= end || address % 2 != 0 {
        return Err("SERVICE_INVENTORY_POINTER".into());
    }
    let count = ((end - address) / 2).min(limit + 1);
    // SAFETY: aligned pointer and complete bounded slice are inside initialized buffer.
    let units = unsafe { std::slice::from_raw_parts(pointer, count) };
    let length = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("SERVICE_INVENTORY_STRING_LIMIT")?;
    String::from_utf16(&units[..length]).map_err(|_| "SERVICE_INVENTORY_UTF16".into())
}

fn executable_path(command: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    if command.len() > 8192 || command.chars().any(char::is_control) {
        return String::new();
    }
    let mut expanded = String::new();
    let mut rest = command;
    let mut variables = 0;
    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let Some(end) = rest[start + 1..].find('%') else {
            return String::new();
        };
        let Some(value) = lookup(&rest[start + 1..start + 1 + end]) else {
            return String::new();
        };
        variables += 1;
        if variables > 32 || expanded.len() + value.len() > 8192 {
            return String::new();
        }
        expanded.push_str(&value);
        rest = &rest[start + end + 2..];
    }
    expanded.push_str(rest);
    // Config arguments can be long; the executable identity keeps the existing
    // 1024-byte policy bound and must never include arguments/credentials.
    let executable = if let Some(quoted) = expanded.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            return String::new();
        };
        if !quoted[end + 1..].is_empty() && !quoted[end + 1..].starts_with(char::is_whitespace) {
            return String::new();
        }
        &quoted[..end]
    } else {
        let lower = expanded.to_ascii_lowercase();
        let Some((end, _)) = lower.match_indices(".exe").find(|(i, _)| {
            expanded[i + 4..].is_empty() || expanded[i + 4..].starts_with(char::is_whitespace)
        }) else {
            return String::new();
        };
        &expanded[..end + 4]
    };
    validate_app_identity(executable)
        .ok()
        .filter(|path| path.contains(":/"))
        .map(|path| path.replace('/', "\\"))
        .unwrap_or_default()
}

fn configuration(manager: SC_HANDLE, name: &str) -> String {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_CONFIG) };
    if handle.is_null() {
        return String::new();
    } // Access denied/deleted: unknown, not supported.
    let handle = ServiceHandle(handle);
    let mut buffer = vec![0usize; 8192 / size_of::<usize>()];
    let mut needed = 0;
    let ok =
        unsafe { QueryServiceConfigW(handle.0, buffer.as_mut_ptr().cast(), 8192, &mut needed) };
    if ok == 0 {
        return String::new();
    }
    // SAFETY: successful API initialized this aligned buffer with QUERY_SERVICE_CONFIGW.
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    wide_in_buffer(&buffer, config.lpBinaryPathName, 4096)
        .map(|value| executable_path(&value, |name| std::env::var(name).ok()))
        .unwrap_or_default()
}

fn state_name(state: u32) -> &'static str {
    match state {
        SERVICE_RUNNING => "Running",
        SERVICE_STOPPED => "Stopped",
        SERVICE_START_PENDING => "Start Pending",
        SERVICE_STOP_PENDING => "Stop Pending",
        SERVICE_CONTINUE_PENDING => "Continue Pending",
        SERVICE_PAUSE_PENDING => "Pause Pending",
        SERVICE_PAUSED => "Paused",
        _ => "Unknown",
    }
}

pub(super) fn enumerate() -> Result<Vec<WindowsServiceInfo>, String> {
    let manager = unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if manager.is_null() {
        return Err(format!("SERVICE_INVENTORY_OPEN_FAILED: {}", unsafe {
            GetLastError()
        }));
    }
    let manager = ServiceHandle(manager);
    // API maximum256KiB. Pagination is bounded and must make progress.
    let mut buffer = vec![0usize; 256 * 1024 / size_of::<usize>()];
    let mut resume = 0;
    let mut services = Vec::new();
    let mut names = std::collections::HashSet::new();
    let mut text_bytes = 0;
    for _ in 0..16 {
        let previous_resume = resume;
        let mut needed = 0;
        let mut count = 0;
        let ok = unsafe {
            EnumServicesStatusExW(
                manager.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(buffer.as_slice()) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                null(),
            )
        };
        let error = if ok == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if ok == 0 && error != ERROR_MORE_DATA {
            return Err(format!("SERVICE_INVENTORY_ENUM_FAILED: {error}"));
        }
        if count as usize
            > std::mem::size_of_val(buffer.as_slice()) / size_of::<ENUM_SERVICE_STATUS_PROCESSW>()
            || services.len() + count as usize > 2048
        {
            return Err("SERVICE_INVENTORY_LIMIT".into());
        }
        for index in 0..count as usize {
            // SAFETY: count/byte bounds checked; API wrote an aligned array of records.
            let row = unsafe {
                std::ptr::read(
                    buffer
                        .as_ptr()
                        .cast::<ENUM_SERVICE_STATUS_PROCESSW>()
                        .add(index),
                )
            };
            let name = wide_in_buffer(&buffer, row.lpServiceName, 256)?;
            if name.is_empty() || !names.insert(name.to_lowercase()) {
                return Err("SERVICE_INVENTORY_CHANGED".into());
            }
            let display_name =
                wide_in_buffer(&buffer, row.lpDisplayName, 1024).unwrap_or_else(|_| name.clone());
            let exe_path = configuration(manager.0, &name);
            text_bytes += name.len() + display_name.len() + exe_path.len();
            if text_bytes > 2 * 1024 * 1024 {
                return Err("SERVICE_INVENTORY_LIMIT".into());
            }
            let kind = row.ServiceStatusProcess.dwServiceType;
            services.push(WindowsServiceInfo {
                name,
                display_name,
                exe_path,
                process_id: row.ServiceStatusProcess.dwProcessId,
                state: state_name(row.ServiceStatusProcess.dwCurrentState).into(),
                service_type: if kind & SERVICE_WIN32_SHARE_PROCESS != 0 {
                    "Share Process"
                } else if kind & SERVICE_WIN32_OWN_PROCESS != 0 {
                    "Own Process"
                } else {
                    "Unknown"
                }
                .into(),
                supported: false,
                reason: None,
            });
        }
        if ok != 0 {
            services.sort_by_key(|row| row.name.to_lowercase());
            return Ok(services);
        }
        if count == 0 || resume == previous_resume {
            return Err("SERVICE_INVENTORY_NO_PROGRESS".into());
        }
    }
    Err("SERVICE_INVENTORY_PAGE_LIMIT".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guarded_utf16_rejects_external_unaligned_unterminated_and_invalid_data() {
        let mut bytes = vec![0usize; 4];
        let pointer = bytes.as_mut_ptr().cast::<u16>();
        unsafe {
            *pointer = 65;
            *pointer.add(1) = 0;
        }
        assert_eq!(wide_in_buffer(&bytes, pointer, 8).unwrap(), "A");
        assert!(wide_in_buffer(&bytes, std::ptr::null(), 8).is_err());
        assert!(wide_in_buffer(&bytes, (pointer as usize + 1) as *const u16, 8).is_err());
        assert!(wide_in_buffer(&bytes, pointer, 0).is_err());
        unsafe {
            *pointer = 0xD800;
        }
        assert!(wide_in_buffer(&bytes, pointer, 8).is_err());
        bytes.fill((usize::MAX / 0xFFFF) * 65);
        assert!(wide_in_buffer(&bytes, bytes.as_ptr().cast(), 8).is_err());
    }
    #[test]
    fn quoted_unicode_environment_paths_keep_only_the_exact_executable() {
        let lookup = |name: &str| (name == "ROOT").then(|| "C:\\Программы".to_string());
        assert_eq!(
            executable_path("\"%ROOT%\\Service\\worker.EXE\" --secret", lookup),
            "C:\\Программы\\Service\\worker.EXE"
        );
        assert_eq!(
            executable_path(
                &format!("C:/Service/worker.exe {}", "x".repeat(2048)),
                |_| None
            ),
            "C:\\Service\\worker.exe"
        );
        for invalid in [
            "%UNKNOWN%\\worker.exe",
            "worker.exe",
            "C:/bad/../worker.exe",
            "C:/bad.txt",
            "C:/bad.exe\n--arg",
        ] {
            assert!(executable_path(invalid, |_| None).is_empty());
        }
    }
    #[test]
    fn missing_configuration_stays_unsupported_and_shared_hosts_remain_blocked() {
        let rows = vec![WindowsServiceInfo {
            name: "unreadable".into(),
            display_name: "Unknown".into(),
            exe_path: String::new(),
            process_id: 0,
            state: state_name(SERVICE_STOPPED).into(),
            service_type: "Own Process".into(),
            supported: false,
            reason: None,
        }];
        assert!(!super::super::classify_services(rows)[0].supported);
        assert_eq!(state_name(SERVICE_START_PENDING), "Start Pending");
        assert_eq!(state_name(999), "Unknown");
    }
}
