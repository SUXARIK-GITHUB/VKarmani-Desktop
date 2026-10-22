use super::*;

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HandoffAction {
    Quit,
    Restart,
    Elevate,
    Update,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandoffTicket {
    pub(crate) id: String,
    pub(crate) action: HandoffAction,
}
struct Pending {
    ticket: HandoffTicket,
    started: Instant,
    sealed: bool,
}
#[derive(Default)]
pub(crate) struct StateHandoff {
    pending: Option<Pending>,
}
fn failure(code: &'static str) -> StateStorageError {
    StateStorageError::new(
        code,
        "Завершение приложения отменено: сохранение или остановка runtime не подтверждены.",
        true,
    )
}
impl StateHandoff {
    fn begin(&mut self, action: HandoffAction) -> Result<HandoffTicket, StateStorageError> {
        self.begin_with_id(action, crate::durable_state::random_state_id()?)
    }
    fn begin_with_id(
        &mut self,
        action: HandoffAction,
        id: String,
    ) -> Result<HandoffTicket, StateStorageError> {
        if id.len() != 48 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(failure("STATE_HANDOFF_INVALID"));
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.sealed || p.started.elapsed() < Duration::from_secs(30))
        {
            return Err(failure("STATE_HANDOFF_BUSY"));
        }
        let ticket = HandoffTicket { id, action };
        self.pending = Some(Pending {
            ticket: ticket.clone(),
            started: Instant::now(),
            sealed: false,
        });
        Ok(ticket)
    }
    fn seal(&mut self, id: &str) -> Result<HandoffAction, StateStorageError> {
        let pending = self
            .pending
            .as_mut()
            .filter(|p| {
                p.ticket.id == id && !p.sealed && p.started.elapsed() < Duration::from_secs(30)
            })
            .ok_or_else(|| failure("STATE_HANDOFF_EXPIRED"))?;
        pending.sealed = true;
        Ok(pending.ticket.action)
    }
    fn cancel(&mut self, id: &str, allow_sealed: bool) -> Result<(), StateStorageError> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|p| p.ticket.id == id && (!p.sealed || allow_sealed))
        {
            return Err(failure("STATE_HANDOFF_CHANGED"));
        }
        self.pending = None;
        Ok(())
    }
    fn update_sealed(&self, id: &str) -> bool {
        self.pending.as_ref().is_some_and(|p| {
            p.ticket.id == id && p.ticket.action == HandoffAction::Update && p.sealed
        })
    }
}

pub(crate) fn begin_state_handoff(
    app: &AppHandle,
    action: HandoffAction,
) -> Result<HandoffTicket, StateStorageError> {
    let state = app.state::<AppState>();
    let ticket = state
        .state_handoff
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?
        .begin(action)?;
    if app.emit("vkarmani://state-handoff", &ticket).is_err() {
        let _ = state
            .state_handoff
            .lock()
            .map(|mut h| h.cancel(&ticket.id, false));
        return Err(failure("STATE_RENDERER_UNAVAILABLE"));
    }
    Ok(ticket)
}
fn seal(
    app: &AppHandle,
    ticket: &str,
    generation: &str,
    revision: &str,
) -> Result<HandoffAction, StateStorageError> {
    let state = app.state::<AppState>();
    let _storage = state
        .storage_lock
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?;
    let snapshot = app_durable_store(app)?.load()?;
    if snapshot.read_only || snapshot.generation != generation || snapshot.revision != revision {
        return Err(failure("STATE_CONFLICT"));
    }
    let action = state
        .state_handoff
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?
        .seal(ticket)?;
    state
        .storage_closed
        .store(true, std::sync::atomic::Ordering::Release);
    Ok(action)
}
fn abort(app: &AppHandle, ticket: &str) {
    let state = app.state::<AppState>();
    // Same lock order as commit and seal; no writer can enter during unseal.
    if let Ok(_storage) = state.storage_lock.lock() {
        if state
            .state_handoff
            .lock()
            .is_ok_and(|mut h| h.cancel(ticket, true).is_ok())
        {
            state
                .exit_approved
                .store(false, std::sync::atomic::Ordering::Release);
            state
                .storage_closed
                .store(false, std::sync::atomic::Ordering::Release);
        }
    };
}
#[tauri::command]
pub(crate) async fn acknowledge_state_handoff(
    ticket: String,
    generation: String,
    revision: String,
    app: AppHandle,
) -> Result<bool, StateStorageError> {
    tauri::async_runtime::spawn_blocking(move || {
        let action = seal(&app, &ticket, &generation, &revision)?;
        let state = app.state::<AppState>();
        let result: Result<bool, StateStorageError> = match action {
            HandoffAction::Restart => crate::restart_lifecycle::restart_after_owned_cleanup(
                &state.restart_requested,
                || cleanup_application(&app, "state_handoff_restart"),
                || {
                    state
                        .exit_approved
                        .store(true, std::sync::atomic::Ordering::Release);
                    app.request_restart();
                },
            )
            .map(|_| true)
            .map_err(|_| failure("STATE_HANDOFF_CLEANUP_FAILED")),
            HandoffAction::Quit => cleanup_application(&app, "state_handoff_quit")
                .map(|_| {
                    state
                        .exit_approved
                        .store(true, std::sync::atomic::Ordering::Release);
                    app.exit(0);
                    true
                })
                .map_err(|_| failure("STATE_HANDOFF_CLEANUP_FAILED")),
            HandoffAction::Elevate => ensure_admin_launch_blocking(app.clone()),
            HandoffAction::Update => Err(failure("STATE_HANDOFF_ACTION_INVALID")),
        };
        match result {
            Ok(true) => Ok(true),
            Ok(false) => {
                abort(&app, &ticket);
                Ok(false)
            }
            Err(error) => {
                abort(&app, &ticket);
                Err(error)
            }
        }
    })
    .await
    .map_err(|_| failure("STATE_TASK_FAILED"))?
}
#[tauri::command]
pub(crate) fn cancel_state_handoff(
    ticket: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let state = app.state::<AppState>();
    let _storage = state
        .storage_lock
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?;
    // A renderer cancellation cannot reopen writes during an active native
    // quit/restart/elevation cleanup. Only a failed update can release its seal.
    let mut h = state
        .state_handoff
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?;
    if h.pending.is_none()
        && !state
            .storage_closed
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(());
    }
    let update = h.update_sealed(&ticket);
    h.cancel(&ticket, update)?;
    state
        .exit_approved
        .store(false, std::sync::atomic::Ordering::Release);
    state
        .storage_closed
        .store(false, std::sync::atomic::Ordering::Release);
    Ok(())
}
#[tauri::command]
pub(crate) fn seal_state_for_update(
    ticket: String,
    generation: String,
    revision: String,
    app: AppHandle,
) -> Result<String, StateStorageError> {
    let ticket = app
        .state::<AppState>()
        .state_handoff
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?
        .begin_with_id(HandoffAction::Update, ticket)?;
    if let Err(error) = seal(&app, &ticket.id, &generation, &revision) {
        abort(&app, &ticket.id);
        return Err(error);
    }
    Ok(ticket.id)
}
#[tauri::command]
pub(crate) fn approve_state_update_exit(
    ticket: String,
    app: AppHandle,
) -> Result<(), StateStorageError> {
    let state = app.state::<AppState>();
    let _storage = state
        .storage_lock
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?;
    if !state
        .state_handoff
        .lock()
        .map_err(|_| failure("STATE_LOCK_FAILED"))?
        .update_sealed(&ticket)
        || state
            .runtime
            .lock()
            .map_err(|_| failure("STATE_LOCK_FAILED"))?
            .is_some()
        || state
            .starting_runtime
            .lock()
            .map_err(|_| failure("STATE_LOCK_FAILED"))?
            .is_some()
    {
        return Err(failure("STATE_UPDATE_RUNTIME_ACTIVE"));
    }
    state
        .exit_approved
        .store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_runtime_mutation_cannot_reopen_after_seal_but_cleanup_and_cancel_can_continue() {
        let state = std::sync::Arc::new(AppState::default());
        let held =
            begin_runtime_operation(&state, Duration::ZERO, "in-flight", Duration::from_secs(5))
                .unwrap();
        let other = state.clone();
        let (started, waiting) = std::sync::mpsc::channel();
        let pending = std::thread::spawn(move || {
            started.send(()).unwrap();
            begin_open_runtime_operation(&other, Duration::from_secs(2), "queued-connect").is_err()
        });
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        state
            .storage_closed
            .store(true, std::sync::atomic::Ordering::Release);
        drop(held);
        assert!(pending.join().unwrap());
        // The seal must never prevent owned disconnect/cleanup itself.
        drop(
            begin_runtime_operation(&state, Duration::ZERO, "disconnect", Duration::from_secs(2))
                .unwrap(),
        );
        state
            .storage_closed
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(
            begin_open_runtime_operation(&state, Duration::ZERO, "after-confirmed-cancel").is_ok()
        );
    }
    #[test]
    fn only_current_unexpired_ticket_can_seal_and_duplicate_cannot_cleanup() {
        let mut h = StateHandoff::default();
        let t = h.begin(HandoffAction::Restart).unwrap();
        assert!(h.begin(HandoffAction::Quit).is_err());
        assert!(h.seal("wrong").is_err());
        assert!(matches!(h.seal(&t.id).unwrap(), HandoffAction::Restart));
        assert!(h.seal(&t.id).is_err());
        assert!(h.cancel(&t.id, false).is_err());
        h.cancel(&t.id, true).unwrap();
        assert!(h.begin(HandoffAction::Quit).is_ok());
    }
    #[test]
    fn expired_request_never_becomes_a_late_shutdown_or_write_freeze() {
        let mut h = StateHandoff::default();
        let old = h.begin(HandoffAction::Quit).unwrap();
        h.pending.as_mut().unwrap().started = Instant::now() - Duration::from_secs(31);
        assert!(h.seal(&old.id).is_err());
        let new = h.begin(HandoffAction::Restart).unwrap();
        assert!(h.cancel(&old.id, true).is_err());
        assert!(h.seal(&new.id).is_ok());
    }
}
