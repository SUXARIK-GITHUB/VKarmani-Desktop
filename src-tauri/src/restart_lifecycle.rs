use std::sync::atomic::{AtomicBool, Ordering};

// The official request_restart path sends ExitRequested and Exit, releasing
// single-instance ownership before Tauri relaunches. Never spawn a second app.
pub(crate) fn restart_after_owned_cleanup(
    pending: &AtomicBool,
    cleanup: impl FnOnce() -> Result<(), String>,
    request_restart: impl FnOnce(),
) -> Result<(), String> {
    if pending.swap(true, Ordering::AcqRel) {
        return Err("Перезапуск приложения уже запрошен.".into());
    }
    if let Err(error) = cleanup() {
        pending.store(false, Ordering::Release);
        return Err(format!(
            "Перезапуск отменён: cleanup не подтверждён: {error}"
        ));
    }
    request_restart();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn cleanup_failure_keeps_app_alive_and_retryable() {
        let pending = AtomicBool::new(false);
        let calls = RefCell::new(Vec::new());
        let result = restart_after_owned_cleanup(
            &pending,
            || {
                calls.borrow_mut().push("cleanup-failed");
                Err("owned journal retained".into())
            },
            || calls.borrow_mut().push("restart"),
        );
        assert!(result.is_err());
        assert!(!pending.load(Ordering::Acquire));
        assert_eq!(*calls.borrow(), ["cleanup-failed"]);
        assert!(restart_after_owned_cleanup(
            &pending,
            || Ok(()),
            || calls.borrow_mut().push("restart")
        )
        .is_ok());
        assert_eq!(*calls.borrow(), ["cleanup-failed", "restart"]);
    }

    #[test]
    fn duplicate_restart_cannot_cleanup_or_relaunch_twice() {
        let pending = AtomicBool::new(false);
        let calls = RefCell::new(Vec::new());
        assert!(restart_after_owned_cleanup(
            &pending,
            || {
                calls.borrow_mut().push("cleanup");
                Ok(())
            },
            || calls.borrow_mut().push("restart")
        )
        .is_ok());
        assert_eq!(*calls.borrow(), ["cleanup", "restart"]);
        assert!(restart_after_owned_cleanup(
            &pending,
            || panic!("duplicate cleanup"),
            || panic!("duplicate restart")
        )
        .is_err());
    }

    #[test]
    fn concurrent_restart_intents_have_one_cleanup_and_one_restart() {
        let pending = AtomicBool::new(false);
        let restarts = std::sync::atomic::AtomicUsize::new(0);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let pending_ref = &pending;
            let restarts_ref = &restarts;
            let first = scope.spawn(move || {
                restart_after_owned_cleanup(
                    pending_ref,
                    || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(())
                    },
                    || {
                        restarts_ref.fetch_add(1, Ordering::AcqRel);
                    },
                )
            });
            entered_rx.recv().unwrap();
            assert!(restart_after_owned_cleanup(
                &pending,
                || panic!("concurrent cleanup"),
                || panic!("concurrent restart"),
            )
            .is_err());
            release_tx.send(()).unwrap();
            assert!(first.join().unwrap().is_ok());
        });
        assert_eq!(restarts.load(Ordering::Acquire), 1);
    }
}
