//! Bounded public receipts, separate from encrypted user state and repair-plan
//! nonces. A corrupt original is preserved; repairs cannot silently erase it.
use super::*;
use serde::Deserialize;
static SERIAL: Mutex<()> = Mutex::new(());
const NAME: &str = "repair-history-v1.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Receipt {
    at_unix_ms: u64,
    code: String,
    restore_proxy: bool,
    route_count: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct History {
    schema_version: u8,
    entries: Vec<Receipt>,
}
fn allowed(code: &str) -> bool {
    matches!(
        code,
        "REPAIR_STARTED"
            | "REPAIR_COMPLETED"
            | "REPAIR_PROXY_UNCONFIRMED"
            | "REPAIR_PARTIAL_ROUTES_UNCONFIRMED"
            | "REPAIR_ROUTES_UNCONFIRMED"
            | "REPAIR_RUNTIME_PRESENT"
            | "REPAIR_BUSY"
            | "REPAIR_EXECUTION_UNCONFIRMED"
    )
}
pub(crate) fn read(root: &Path) -> Result<Vec<Receipt>, String> {
    let text =
        read_state_file(&root.join(NAME), 16384).map_err(|_| "REPAIR_HISTORY_UNAVAILABLE")?;
    let Some(text) = text else { return Ok(vec![]) };
    let history: History = serde_json::from_str(&text).map_err(|_| "REPAIR_HISTORY_INVALID")?;
    if history.schema_version != 1
        || history.entries.len() > 32
        || history
            .entries
            .iter()
            .any(|e| !allowed(&e.code) || e.route_count > 4 || e.at_unix_ms > 8640000000000000)
    {
        return Err("REPAIR_HISTORY_INVALID".into());
    }
    Ok(history.entries)
}
pub(crate) fn record(
    root: &Path,
    code: &str,
    restore_proxy: bool,
    route_count: usize,
) -> Result<(), String> {
    let _serial = SERIAL.lock().map_err(|_| "REPAIR_HISTORY_UNAVAILABLE")?;
    if !allowed(code) || route_count > 4 {
        return Err("REPAIR_HISTORY_INVALID".into());
    }
    let mut entries = read(root)?;
    entries.push(Receipt {
        at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        code: code.into(),
        restore_proxy,
        route_count,
    });
    if entries.len() > 32 {
        entries.drain(..entries.len() - 32);
    }
    let text = serde_json::to_string(&History {
        schema_version: 1,
        entries,
    })
    .map_err(|_| "REPAIR_HISTORY_INVALID")?;
    atomic_write_state_text_with_limit(&root.join(NAME), &text, 16384)
        .map_err(|_| "REPAIR_HISTORY_UNAVAILABLE".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_public_history_and_corruption_preservation() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-repair-history-{}",
            crate::durable_state::random_state_id().unwrap()
        ));
        assert!(read(&root).unwrap().is_empty());
        assert!(!root.exists());
        for _ in 0..40 {
            record(&root, "REPAIR_STARTED", true, 2).unwrap();
        }
        assert_eq!(read(&root).unwrap().len(), 32);
        assert!(record(&root, "https://synthetic-private.invalid/key", false, 0).is_err());
        let file = root.join(NAME);
        fs::write(&file, "{invalid synthetic").unwrap();
        assert!(record(&root, "REPAIR_COMPLETED", false, 0).is_err());
        assert_eq!(fs::read_to_string(&file).unwrap(), "{invalid synthetic");
        fs::remove_file(file).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
