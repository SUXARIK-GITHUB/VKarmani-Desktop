//! Read-only observations. No launch/staging, DPAPI load/migration, log tree
//! creation, network repair or external requests are allowed here.
use super::*;
#[cfg(target_os = "windows")]
mod ports;
#[cfg(target_os = "windows")]
pub(crate) use ports::runtime_ports_ready;
#[derive(Serialize)]
pub(crate) struct PortObservation {
    port: u16,
    state: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticFacts {
    checked_at_unix_ms: u64,
    resource_integrity: &'static str,
    storage_metadata: &'static str,
    logs_metadata: &'static str,
    elevation: &'static str,
    pub(crate) repair_history: Vec<crate::repair_history::Receipt>,
    repair_history_status: &'static str,
    ports: Vec<PortObservation>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticSnapshot {
    #[serde(flatten)]
    runtime: RuntimeStatus,
    diagnostic_facts: DiagnosticFacts,
}
fn metadata_only(path: &Path, directory: bool) -> &'static str {
    let result = if directory {
        state_directory_guards(path, false).map(|_| ())
    } else {
        path.parent()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))
            .and_then(|parent| {
                let _guards = state_directory_guards(parent, false)?;
                let metadata = fs::symlink_metadata(path)?;
                if metadata.file_type().is_symlink() {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                let mut options = OpenOptions::new();
                options.read(true);
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    options.custom_flags(
                        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                    );
                }
                let file = options.open(path)?;
                check_state_file(&file)
            })
    };
    match result {
        Ok(()) => "present",
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing",
        Err(_) => "unavailable",
    }
}
fn pinned_resources(root: &Path) -> &'static str {
    for name in ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"] {
        let Ok((size, hash)) = compiled_artifact_identity(name) else {
            return "unavailable";
        };
        let bytes = match read_state_bytes(&root.join(name), size) {
            Ok(Some(bytes)) => bytes,
            _ => return "unavailable",
        };
        if bytes.len() as u64 != size || sha256_hex_bytes(&bytes) != hash.to_ascii_lowercase() {
            return "mismatch";
        }
    }
    "verified"
}
pub(crate) fn collect(app: &AppHandle, state: tauri::State<'_, AppState>) -> DiagnosticSnapshot {
    let runtime = read_runtime_status(app, state);
    #[cfg(target_os = "windows")]
    let mut observed_ports =
        ports::observe(if runtime.tunnel_active && runtime.operation.is_none() {
            runtime.xray_pid
        } else {
            None
        });
    #[cfg(not(target_os = "windows"))]
    let observed_ports = [SOCKS_PORT, HTTP_PORT, XRAY_API_PORT]
        .into_iter()
        .map(|port| PortObservation {
            port,
            state: "unavailable",
        })
        .collect::<Vec<_>>();
    #[cfg(target_os = "windows")]
    {
        // Recheck native lease revision and the retained process handle after
        // the table query. A racing runtime is unknown, never owned/free.
        let state = app.state::<AppState>();
        let stable_revision = state
            .operation_machine
            .lock()
            .is_ok_and(|m| m.revision == runtime.runtime_revision && m.current.is_none());
        let stable_process = state
            .runtime
            .lock()
            .is_ok_and(|mut slot| match slot.as_mut() {
                Some(core) => {
                    runtime.tunnel_active
                        && runtime.xray_pid == Some(core.child.id())
                        && matches!(core.child.try_wait(), Ok(None))
                }
                None => !runtime.tunnel_active && runtime.xray_pid.is_none(),
            });
        if !stable_revision || !stable_process || runtime.operation.is_some() {
            for port in &mut observed_ports {
                port.state = "unconfirmed";
            }
        }
    }
    let root = app.path().app_local_data_dir().ok();
    let (repair_history, repair_history_status) =
        match root.as_ref().map(|root| crate::repair_history::read(root)) {
            Some(Ok(receipts)) => (receipts, "available"),
            _ => (vec![], "unavailable"),
        };
    let facts = DiagnosticFacts {
        checked_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        resource_integrity: runtime
            .core_path
            .as_ref()
            .and_then(|path| Path::new(path).parent())
            .map(pinned_resources)
            .unwrap_or("unavailable"),
        storage_metadata: root
            .as_ref()
            .map(|root| metadata_only(&root.join(crate::durable_state::V2_NAME), false))
            .unwrap_or("unavailable"),
        logs_metadata: root
            .as_ref()
            .map(|root| metadata_only(&root.join("logs/rolling-v1"), true))
            .unwrap_or("unavailable"),
        elevation: match is_process_elevated() {
            Ok(true) => "elevated",
            Ok(false) => "standard",
            Err(_) => "unavailable",
        },
        repair_history,
        repair_history_status,
        ports: observed_ports,
    };
    DiagnosticSnapshot {
        runtime,
        diagnostic_facts: facts,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_metadata_observation_creates_nothing() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-diagnostics-{}-{}",
            std::process::id(),
            crate::durable_state::random_state_id().unwrap()
        ));
        assert_eq!(metadata_only(&root.join("state"), false), "missing");
        assert_eq!(metadata_only(&root.join("logs"), true), "missing");
        assert!(!root.exists());
    }
    #[test]
    fn missing_or_tampered_resources_never_pass() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-diagnostics-resources-{}",
            crate::durable_state::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        assert_eq!(pinned_resources(&root), "unavailable");
        fs::write(root.join("xray.exe"), b"invalid synthetic artifact").unwrap();
        assert_eq!(pinned_resources(&root), "mismatch");
        fs::remove_file(root.join("xray.exe")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
