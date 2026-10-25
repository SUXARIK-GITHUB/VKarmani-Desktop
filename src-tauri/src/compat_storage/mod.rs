//! Compatibility exception for the 0.13.76 UI: retain the established encrypted
//! v2 authority and CAS protocol instead of downgrading working state to v1.
use super::*;
mod io;
use io::*;
mod client;
use client::*;
pub(crate) mod durable;
use durable::*;
pub(crate) mod ipc;

fn is_allowed_client_state_key(key: &str) -> bool {
    // Existing v2 history remains valid and preserved; the076 UI exposes none.
    super::is_allowed_client_state_key(key) || key == "sessionHistory"
}

pub(crate) fn snapshot(app: &AppHandle) -> Result<DurableSnapshot, String> {
    let state = app.state::<AppState>();
    let _guard = state.storage_lock.lock().map_err(|_| "STATE_WRITER_BUSY")?;
    let snapshot = ipc::app_durable_store(app)?.load().map_err(|e| e.message)?;
    if snapshot.read_only {
        return Err("STATE_RECOVERY_REQUIRED: original state preserved".into());
    }
    Ok(snapshot)
}

pub(crate) fn reject_legacy_write() -> String {
    ipc::legacy_write_rejected().message
}

impl From<StateStorageError> for String {
    fn from(error: StateStorageError) -> Self {
        format!("{}: {}", error.code, error.message)
    }
}
