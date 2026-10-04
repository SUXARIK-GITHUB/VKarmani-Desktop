use super::*;
use std::sync::atomic::Ordering;

// Armed only after the previous runtime was confirmed stopped. Drop runs while
// the caller still holds its operation lease, including every pre-child error.
pub(crate) struct FailedConnectRollback<F: FnOnce()> {
    cleanup: Option<F>,
}
impl<F: FnOnce()> FailedConnectRollback<F> {
    pub(crate) fn new(cleanup: F) -> Self {
        Self {
            cleanup: Some(cleanup),
        }
    }
    pub(crate) fn commit(&mut self) {
        self.cleanup.take();
    }
}
impl<F: FnOnce()> Drop for FailedConnectRollback<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

pub(crate) fn require_runtime_config_identity(
    actual: Option<&str>,
    expected: &str,
) -> Result<(), String> {
    if expected.is_empty() || actual != Some(expected) {
        return Err("RUNTIME_SUPERSEDED: runtime принадлежит другому действию.".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OperationStatus {
    pub(crate) id: u64,
    pub(crate) kind: String,
    pub(crate) stage: String,
    pub(crate) started_at: u64,
    pub(crate) deadline_at: u64,
    pub(crate) outcome: Option<String>,
    #[serde(skip)]
    generation: u64,
    #[serde(skip)]
    deadline: Instant,
}
#[derive(Default)]
pub(crate) struct OperationMachine {
    pub(crate) revision: u64,
    next_id: u64,
    pub(crate) current: Option<OperationStatus>,
    pub(crate) last: Option<OperationStatus>,
}
pub(crate) struct OperationLease<'a> {
    _serialization: MutexGuard<'a, ()>,
    state: &'a AppState,
    id: u64,
    completed: bool,
}
impl OperationLease<'_> {
    pub(crate) fn check(&self) -> Result<(), String> {
        check_current_operation(self.state)
    }
    pub(crate) fn stage(&self, stage: &str) -> Result<(), String> {
        self.check()?;
        let mut machine = self
            .state
            .operation_machine
            .lock()
            .map_err(|_| "Повреждён runtime operation state".to_string())?;
        if let Some(current) = machine
            .current
            .as_mut()
            .filter(|operation| operation.id == self.id)
        {
            current.stage = stage.into();
        }
        machine.revision += 1;
        Ok(())
    }
    pub(crate) fn commit(&mut self) {
        self.completed = true;
    }
}
impl Drop for OperationLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut machine) = self.state.operation_machine.lock() {
            if machine.current.as_ref().map(|operation| operation.id) == Some(self.id) {
                let mut operation = machine.current.take().expect("checked operation");
                operation.outcome = Some(
                    if self.completed {
                        "completed"
                    } else if self.state.operation_generation.load(Ordering::Acquire)
                        != operation.generation
                    {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into(),
                );
                machine.last = Some(operation);
                machine.revision += 1;
            }
        }
    }
}
pub(crate) fn adopt_runtime_operation<'a>(
    state: &'a AppState,
    serialization: MutexGuard<'a, ()>,
    kind: &str,
    duration: Duration,
) -> Result<OperationLease<'a>, String> {
    let mut machine = state
        .operation_machine
        .lock()
        .map_err(|_| "Runtime operation state повреждён.".to_string())?;
    machine.next_id += 1;
    let id = machine.next_id;
    let now = unix_timestamp_seconds();
    machine.current = Some(OperationStatus {
        id,
        kind: kind.into(),
        stage: "preflight".into(),
        started_at: now,
        deadline_at: now.saturating_add(duration.as_secs()),
        outcome: None,
        generation: state.operation_generation.load(Ordering::Acquire),
        deadline: Instant::now() + duration,
    });
    machine.revision += 1;
    drop(machine);
    Ok(OperationLease {
        _serialization: serialization,
        state,
        id,
        completed: false,
    })
}
pub(crate) fn begin_runtime_operation<'a>(
    state: &'a AppState,
    wait: Duration,
    kind: &str,
    duration: Duration,
) -> Result<OperationLease<'a>, String> {
    let started = Instant::now();
    let generation = state.operation_generation.load(Ordering::Acquire);
    let serialization = loop {
        if state.operation_generation.load(Ordering::Acquire) != generation {
            return Err("OPERATION_CANCELLED: ожидавшее runtime действие отменено.".into());
        }
        match state.operation_lock.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("Runtime operation lock повреждён.".into())
            }
            Err(_) if started.elapsed() < wait => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                return Err(format!(
                    "Runtime уже выполняет другое действие ({kind}). Повторите позже."
                ))
            }
        }
    };
    adopt_runtime_operation(state, serialization, kind, duration)
}
pub(crate) fn check_current_operation(state: &AppState) -> Result<(), String> {
    let machine = state
        .operation_machine
        .lock()
        .map_err(|_| "Runtime operation state повреждён.".to_string())?;
    if let Some(operation) = &machine.current {
        if state.operation_generation.load(Ordering::Acquire) != operation.generation {
            return Err(
                "OPERATION_CANCELLED: runtime действие отменено запросом отключения.".into(),
            );
        }
        if Instant::now() >= operation.deadline {
            return Err("OPERATION_DEADLINE: runtime действие не завершилось в срок.".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_cancellation_corpus_preserves_exclusion_and_allows_next_operation() {
        let state = std::sync::Arc::new(AppState::default());
        let in_critical = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let state = state.clone();
                let in_critical = in_critical.clone();
                std::thread::spawn(move || {
                    for index in 0..64 {
                        let mut cancelled_waits = 0;
                        let mut op = loop {
                            match begin_runtime_operation(
                                &state,
                                Duration::from_secs(5),
                                "corpus",
                                Duration::from_secs(1),
                            ) {
                                Ok(lease) => break lease,
                                Err(error) if error.starts_with("OPERATION_CANCELLED") => {
                                    // Cancellation invalidates pending generations too.
                                    cancelled_waits += 1;
                                    assert!(cancelled_waits <= 512);
                                }
                                Err(error) => panic!("unexpected coordinator failure: {error}"),
                            }
                        };
                        assert_eq!(in_critical.fetch_add(1, Ordering::AcqRel), 0);
                        op.stage("working").unwrap();
                        if (worker + index) % 7 == 0 {
                            state.operation_generation.fetch_add(1, Ordering::AcqRel);
                            assert!(op.check().unwrap_err().starts_with("OPERATION_CANCELLED"));
                        } else {
                            op.check().unwrap();
                            op.commit();
                        }
                        assert_eq!(in_critical.fetch_sub(1, Ordering::AcqRel), 1);
                        drop(op);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let machine = state.operation_machine.lock().unwrap();
        assert!(machine.current.is_none());
        assert_eq!(machine.last.as_ref().unwrap().id, 512);
        assert_eq!(in_critical.load(Ordering::Acquire), 0);
    }
    #[test]
    fn stale_connect_cleanup_cannot_cancel_or_restore_a_newer_generation() {
        let state = AppState::default();
        let generation = state.operation_generation.load(Ordering::Acquire);
        assert!(require_runtime_config_identity(Some("unique-C.json"), "unique-B.json").is_err());
        assert!(require_runtime_config_identity(None, "unique-B.json").is_err());
        assert!(require_runtime_config_identity(Some("unique-C.json"), "").is_err());
        assert_eq!(
            state.operation_generation.load(Ordering::Acquire),
            generation
        );
        assert!(require_runtime_config_identity(Some("unique-C.json"), "unique-C.json").is_ok());
    }
    #[test]
    fn serializes_operations_records_outcome_and_cooperatively_cancels() {
        let state = AppState::default();
        let mut lease =
            begin_runtime_operation(&state, Duration::ZERO, "connect", Duration::from_secs(1))
                .unwrap();
        lease.stage("starting").unwrap();
        assert!(begin_runtime_operation(
            &state,
            Duration::from_millis(1),
            "connect",
            Duration::from_secs(1)
        )
        .is_err());
        state.operation_generation.fetch_add(1, Ordering::AcqRel);
        assert!(lease
            .check()
            .unwrap_err()
            .starts_with("OPERATION_CANCELLED"));
        drop(lease);
        assert_eq!(
            state
                .operation_machine
                .lock()
                .unwrap()
                .last
                .as_ref()
                .unwrap()
                .outcome
                .as_deref(),
            Some("cancelled")
        );
        lease =
            begin_runtime_operation(&state, Duration::ZERO, "disconnect", Duration::from_secs(1))
                .unwrap();
        lease.stage("disconnected").unwrap();
        lease.commit();
        drop(lease);
        assert!(state.operation_machine.lock().unwrap().current.is_none());
        assert_eq!(
            state
                .operation_machine
                .lock()
                .unwrap()
                .last
                .as_ref()
                .unwrap()
                .id,
            2
        );
    }
    #[test]
    fn deadline_failure_and_100_concurrent_owned_operation_sequences() {
        let state = std::sync::Arc::new(AppState::default());
        let lease =
            begin_runtime_operation(&state, Duration::ZERO, "probe", Duration::ZERO).unwrap();
        assert!(lease.check().unwrap_err().starts_with("OPERATION_DEADLINE"));
        drop(lease);
        let workers = (0..4)
            .map(|_| {
                let state = state.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        let mut op = begin_runtime_operation(
                            &state,
                            Duration::from_secs(3),
                            "test",
                            Duration::from_secs(1),
                        )
                        .unwrap();
                        op.stage("working").unwrap();
                        op.commit();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        let machine = state.operation_machine.lock().unwrap();
        assert!(machine.current.is_none());
        assert_eq!(machine.last.as_ref().unwrap().id, 101);
        // Coordinator stress only. No native network connect/disconnect claim.
    }
}
