use super::durable::{DurableSnapshot, DurableStore, StateCommit, StatePatch};
use super::*;

pub(crate) fn app_durable_store(app: &AppHandle) -> Result<DurableStore, StateStorageError> {
    let root = app.path().app_local_data_dir().map_err(|_| {
        StateStorageError::new(
            "STATE_PATH_UNAVAILABLE",
            "Не удалось определить каталог состояния.",
            true,
        )
    })?;
    Ok(DurableStore::at(root))
}
fn task_error() -> StateStorageError {
    StateStorageError::new(
        "STATE_TASK_FAILED",
        "Операция с хранилищем была прервана.",
        true,
    )
}
pub(crate) fn legacy_write_rejected() -> StateStorageError {
    StateStorageError::new(
        "STATE_PROTOCOL_REQUIRED",
        "Требуется native state v2 с generation/revision. Сохранённые данные не изменены.",
        false,
    )
}

#[tauri::command]
pub(crate) async fn load_state_snapshot(
    app: AppHandle,
) -> Result<DurableSnapshot, StateStorageError> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = state.storage_lock.lock().map_err(|_| task_error())?;
        app_durable_store(&app)?.load()
    })
    .await
    .map_err(|_| task_error())?
}
#[tauri::command]
pub(crate) async fn commit_state_patch(
    request: StatePatch,
    app: AppHandle,
) -> Result<StateCommit, StateStorageError> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = state.storage_lock.lock().map_err(|_| task_error())?;
        if state
            .storage_closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(StateStorageError::new(
                "STATE_CLOSING",
                "Сохранение остановлено на время завершения приложения.",
                true,
            ));
        }
        app_durable_store(&app)?.patch(request)
    })
    .await
    .map_err(|_| task_error())?
}
#[tauri::command]
pub(crate) async fn recover_state_snapshot(
    token: String,
    app: AppHandle,
) -> Result<DurableSnapshot, StateStorageError> {
    if token.len() != 64 {
        return Err(task_error());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = state.storage_lock.lock().map_err(|_| task_error())?;
        if state
            .storage_closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(task_error());
        }
        app_durable_store(&app)?.recover(&token)
    })
    .await
    .map_err(|_| task_error())?
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyExportReceipt {
    directory: String,
    generation: String,
    revision: String,
}
#[tauri::command]
pub(crate) async fn export_state_legacy(
    generation: String,
    revision: String,
    app: AppHandle,
) -> Result<LegacyExportReceipt, StateStorageError> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = state.storage_lock.lock().map_err(|_| task_error())?;
        // This only prepares a new rollback package. Activation is a separate
        // offline step after both application versions have stopped.
        if state.runtime.lock().map_err(|_| task_error())?.is_some()
            || state
                .starting_runtime
                .lock()
                .map_err(|_| task_error())?
                .is_some()
        {
            return Err(StateStorageError::new(
                "STATE_EXPORT_RUNTIME_ACTIVE",
                "Подготовка rollback требует остановленного runtime кандидата.",
                true,
            ));
        }
        let directory = app_durable_store(&app)?.export_legacy(&generation, &revision)?;
        Ok(LegacyExportReceipt {
            directory: directory.to_string_lossy().into_owned(),
            generation,
            revision,
        })
    })
    .await
    .map_err(|_| task_error())?
}
