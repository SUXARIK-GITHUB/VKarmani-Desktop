use super::*;

pub(crate) fn ensure_previous_owner_inactive(owner_pid: u32) -> Result<(), String> {
    if owner_pid == 0 {
        return Err("OWNER_UNKNOWN: no process identity".into());
    }
    if owner_pid == std::process::id() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Threading::*;
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                owner_pid,
            )
        };
        if handle.is_null() {
            return if std::io::Error::last_os_error().raw_os_error() == Some(87) {
                Ok(())
            } else {
                Err("OWNER_UNKNOWN: previous process cannot be checked".into())
            };
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        if wait != 0 {
            return Err("OWNER_ACTIVE: previous owner may still be running".into());
        }
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("OWNER_UNKNOWN: unsupported platform".into())
    }
}

// The only termination authority is a retained OS handle. The job handle is
// non-inheritable and KILL_ON_JOB_CLOSE, so owner-process death closes the job.
pub(crate) struct OwnedXrayProcess {
    child: Child,
    integrity: Option<std::sync::Arc<LaunchIntegrity>>,
    #[cfg(target_os = "windows")]
    _job: Option<JobHandle>,
}
#[cfg(target_os = "windows")]
struct JobHandle(windows_sys::Win32::Foundation::HANDLE);
#[cfg(target_os = "windows")]
unsafe impl Send for JobHandle {} // Unique owned kernel handle, never shared as an API pointer.
#[cfg(target_os = "windows")]
impl Drop for JobHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
impl OwnedXrayProcess {
    pub(crate) fn with_integrity(mut self, integrity: LaunchIntegrity) -> Self {
        self.integrity = Some(std::sync::Arc::new(integrity));
        self
    }
    pub(crate) fn integrity_lease(&self) -> Option<std::sync::Arc<LaunchIntegrity>> {
        self.integrity.clone()
    }
    pub(crate) fn release_integrity(&mut self) {
        #[cfg(target_os = "windows")]
        self._job.take();
        self.integrity.take();
    }
    pub(crate) fn attach(mut child: Child) -> Result<Self, String> {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::*;
            let handle = unsafe { CreateJobObjectW(null(), null()) };
            if handle.is_null() {
                let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(2));
                return Err("PROCESS_OWNERSHIP_FAILED: job creation failed".into());
            }
            let job = JobHandle(handle);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } != 0;
            let assigned = configured
                && unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } != 0;
            if !assigned {
                let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(2));
                return Err("PROCESS_OWNERSHIP_FAILED: job assignment failed".into());
            }
            Ok(Self {
                child,
                _job: Some(job),
                integrity: None,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(Self {
                child,
                integrity: None,
            })
        }
    }
}
impl Drop for OwnedXrayProcess {
    fn drop(&mut self) {
        self.release_integrity();
    }
}
impl std::ops::Deref for OwnedXrayProcess {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl std::ops::DerefMut for OwnedXrayProcess {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    #[test]
    fn refuses_live_previous_owner_and_missing_identity() {
        assert!(ensure_previous_owner_inactive(0).is_err());
        assert!(ensure_previous_owner_inactive(std::process::id()).is_ok());
        let mut command =
            Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 20",
        ]);
        hide_child_console(&mut command);
        let child = OwnedXrayProcess::attach(command.spawn().unwrap()).unwrap();
        assert!(ensure_previous_owner_inactive(child.id())
            .unwrap_err()
            .starts_with("OWNER_ACTIVE"));
        drop(child);
    }
    #[test]
    fn dropping_job_terminates_only_attached_synthetic_process() {
        use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject};
        let mut command =
            Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 20",
        ]);
        hide_child_console(&mut command);
        let child = command.spawn().unwrap();
        let current = unsafe { GetCurrentProcess() };
        let mut retained = null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    current,
                    child.as_raw_handle(),
                    current,
                    &mut retained,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let owned = OwnedXrayProcess::attach(child).unwrap();
        assert_eq!(unsafe { WaitForSingleObject(retained, 0) }, 258);
        drop(owned);
        assert_eq!(unsafe { WaitForSingleObject(retained, 3000) }, 0);
        unsafe {
            CloseHandle(retained);
        }
    }
}
