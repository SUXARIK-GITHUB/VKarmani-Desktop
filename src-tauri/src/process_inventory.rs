//! Read-only Windows process inventory. Handles grant query rights only.
use super::*;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        CopySid, EqualSid, GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
            QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

struct QueryHandle(HANDLE);
impl QueryHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(Self(handle))
    }
}
impl Drop for QueryHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(crate) fn owner_sid(process: HANDLE) -> Option<Vec<u32>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = QueryHandle::new(token)?;
    // TOKEN_USER plus the maximum Windows SID fits in this aligned buffer.
    let mut buffer = [0usize; 128];
    let mut used = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            std::mem::size_of_val(&buffer) as u32,
            &mut used,
        )
    } == 0
        || used < std::mem::size_of::<TOKEN_USER>() as u32
        || used as usize > std::mem::size_of_val(&buffer)
    {
        return None;
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let start = buffer.as_ptr() as usize;
    let end = start.checked_add(used as usize)?;
    let sid_start = user.User.Sid as usize;
    if sid_start < start || sid_start.checked_add(8)? > end {
        return None;
    }
    let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
    if !(8..=68).contains(&length) || sid_start.checked_add(length)? > end {
        return None;
    }
    let mut sid = vec![0u32; length.div_ceil(4)];
    (unsafe { CopySid(length as u32, sid.as_mut_ptr().cast(), user.User.Sid) } != 0).then_some(sid)
}

fn session_id(pid: u32) -> Option<u32> {
    let mut session = 0;
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

pub(crate) fn native_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    let session =
        session_id(unsafe { GetCurrentProcessId() }).ok_or("APP_INVENTORY_SESSION_UNAVAILABLE")?;
    let current_sid =
        owner_sid(unsafe { GetCurrentProcess() }).ok_or("APP_INVENTORY_OWNER_UNAVAILABLE")?;
    let snapshot = QueryHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
        .ok_or("APP_INVENTORY_SNAPSHOT_UNAVAILABLE")?;
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut present = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
    let mut enumeration_error = if present {
        0
    } else {
        unsafe { GetLastError() }
    };
    let mut apps = Vec::new();
    let mut scanned = 0usize;
    let mut path = vec![0u16; 32768];
    loop {
        if !present {
            return if enumeration_error == ERROR_NO_MORE_FILES {
                prepare_running_app_inventory(apps, 4096)
            } else {
                Err("APP_INVENTORY_ENUMERATION_FAILED".into())
            };
        }
        scanned += 1;
        if scanned > 16384 {
            return Err("APP_INVENTORY_LIMIT: process snapshot exceeds bound".into());
        }
        let end = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        if name.to_ascii_lowercase().ends_with(".exe") {
            let process = QueryHandle::new(unsafe {
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID)
            });
            let same_session = session_id(entry.th32ProcessID) == Some(session);
            let same_owner = !same_session && process.as_ref().and_then(|handle| owner_sid(handle.0)).is_some_and(|sid|
                unsafe { EqualSid(current_sid.as_ptr().cast_mut().cast(), sid.as_ptr().cast_mut().cast()) } != 0);
            if same_session || same_owner {
                let executable = process.as_ref().and_then(|handle| {
                    let mut length = path.len() as u32;
                    if unsafe {
                        QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length)
                    } == 0
                        || length as usize >= path.len()
                    {
                        return None;
                    }
                    Some(String::from_utf16_lossy(&path[..length as usize]))
                });
                apps.push(RunningAppInfo {
                    pid: entry.th32ProcessID,
                    name,
                    path: executable,
                    title: None,
                });
                if apps.len() > 4096 {
                    return Err("APP_INVENTORY_LIMIT: application list exceeds bound".into());
                }
            }
        }
        present = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        enumeration_error = if present {
            0
        } else {
            unsafe { GetLastError() }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_query_handles_and_unavailable_owner_are_not_admitted() {
        assert!(QueryHandle::new(null_mut()).is_none());
        assert!(QueryHandle::new(INVALID_HANDLE_VALUE).is_none());
        assert!(owner_sid(null_mut()).is_none());
    }
    #[test]
    fn read_only_native_inventory_contains_its_own_exact_executable() {
        let apps = native_running_apps().unwrap();
        let own = apps
            .iter()
            .find(|app| app.pid == std::process::id())
            .unwrap();
        let path = own.path.as_ref().unwrap().replace('\\', "/");
        assert!(path.eq_ignore_ascii_case(
            &std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        ));
        assert!(apps.len() <= 4096);
    }
    #[test]
    #[ignore = "owned isolated helper; exercised by inventory_reader_releases_handles"]
    fn inventory_handle_lifetime_helper() {
        if std::env::var("VKARMANI_INVENTORY_HELPER").as_deref() != Ok("1") {
            return;
        }
        use windows_sys::Win32::System::Threading::GetProcessHandleCount;
        native_running_apps().unwrap();
        let mut before = 0;
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut before) },
            0
        );
        let started = Instant::now();
        for _ in 0..20 {
            native_running_apps().unwrap();
        }
        let mut after = 0;
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut after) },
            0
        );
        assert!(
            after <= before + 2,
            "Query handles accumulated: {before} -> {after}"
        );
        println!("inventory-owned-helper: cycles=20; durationMs={}; handlesBefore={before}; handlesAfter={after}",started.elapsed().as_millis());
    }
    #[test]
    fn inventory_reader_releases_handles() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_inventory::tests::inventory_handle_lifetime_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("VKARMANI_INVENTORY_HELPER", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
    #[test]
    #[ignore = "explicit read-only native/fallback benchmark; no application or network actions"]
    fn inventory_native_vs_fallback_read_only_benchmark() {
        let before = Instant::now();
        let native = native_running_apps().unwrap();
        let native_ms = before.elapsed().as_millis();
        let before = Instant::now();
        let fallback = list_running_apps_fallback().unwrap();
        let fallback_ms = before.elapsed().as_millis();
        assert!(native.iter().any(|app| app.pid == std::process::id()));
        assert!(fallback.iter().any(|app| app.pid == std::process::id()));
        println!("inventory-read-only-comparison: nativeMs={native_ms}; fallbackMs={fallback_ms}; nativeCount={}; fallbackCount={}; nativeHasOwnerAndSessionFilter=true; processChurnNotControlled=true",native.len(),fallback.len());
    }
}
