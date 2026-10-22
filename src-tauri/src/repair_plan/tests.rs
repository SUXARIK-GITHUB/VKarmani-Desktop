use super::*;
#[test]
fn receipt_failure_prevents_effects_and_partial_failure_has_a_durable_public_outcome() {
    let root = std::env::temp_dir().join(format!(
        "vkarmani-recorded-repair-{}",
        crate::durable_state::random_state_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    let file = root.join("repair-history-v1.json");
    fs::write(&file, "invalid original").unwrap();
    let plan = RepairPlan {
        id: "a".repeat(48),
        expires_after_ms: 30000,
        restore_proxy: true,
        remove_route_count: 2,
    };
    let mut backend = Fake {
        calls: vec![],
        fail: None,
        checks: 0,
    };
    assert_eq!(
        apply_recorded(&root, &plan, &mut backend).unwrap_err(),
        "REPAIR_HISTORY_INVALID"
    );
    assert!(backend.calls.is_empty());
    assert_eq!(fs::read_to_string(&file).unwrap(), "invalid original");
    fs::remove_file(&file).unwrap();
    backend.fail = Some("routes");
    assert_eq!(
        apply_recorded(&root, &plan, &mut backend).unwrap_err(),
        "REPAIR_PARTIAL_ROUTES_UNCONFIRMED"
    );
    let receipts = serde_json::to_value(crate::repair_history::read(&root).unwrap()).unwrap();
    assert_eq!(receipts[0]["code"], "REPAIR_STARTED");
    assert_eq!(receipts[1]["code"], "REPAIR_PARTIAL_ROUTES_UNCONFIRMED");
    assert_eq!(backend.calls, ["check", "proxy", "check", "routes"]);
    assert!(!receipts.to_string().contains(&plan.id));
    fs::remove_file(file).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn completed_effects_are_not_reversed_when_terminal_receipt_cannot_be_saved() {
    let root = std::env::temp_dir().join(format!(
        "vkarmani-terminal-repair-{}",
        crate::durable_state::random_state_id().unwrap()
    ));
    struct BackendWithCorruption {
        root: PathBuf,
        calls: Vec<&'static str>,
    }
    impl Backend for BackendWithCorruption {
        fn check(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn proxy(&mut self) -> Result<(), String> {
            self.calls.push("proxy-restored");
            Ok(())
        }
        fn routes(&mut self) -> Result<(), String> {
            self.calls.push("routes-cleaned");
            Ok(())
        }
        fn verify(&mut self) -> Result<(), String> {
            fs::write(
                self.root.join("repair-history-v1.json"),
                "corrupt after effects",
            )
            .unwrap();
            Ok(())
        }
    }
    let mut backend = BackendWithCorruption {
        root: root.clone(),
        calls: vec![],
    };
    let plan = RepairPlan {
        id: "a".repeat(48),
        expires_after_ms: 30000,
        restore_proxy: true,
        remove_route_count: 2,
    };
    assert_eq!(
        apply_recorded(&root, &plan, &mut backend).unwrap_err(),
        "REPAIR_RECEIPT_UNCONFIRMED"
    );
    assert_eq!(backend.calls, ["proxy-restored", "routes-cleaned"]);
    assert_eq!(
        fs::read_to_string(root.join("repair-history-v1.json")).unwrap(),
        "corrupt after effects"
    );
    fs::remove_file(root.join("repair-history-v1.json")).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn public_failure_keeps_machine_code_without_private_payload_or_false_retry() {
    let failure = public_error("private PAC and path");
    let value = serde_json::to_value(failure).unwrap();
    assert_eq!(value["code"], "REPAIR_EXECUTION_UNCONFIRMED");
    assert_eq!(value["retryable"], false);
    assert!(!value.to_string().contains("private"));
    assert_eq!(
        serde_json::to_value(public_error("REPAIR_PLAN_STALE")).unwrap()["retryable"],
        true
    );
}
#[test]
fn consent_is_single_use_expires_and_cannot_be_replayed_after_new_plan_or_state_change() {
    let mut store = RepairPlans::default();
    let now = Instant::now();
    let old = store.issue("a".into(), true, 4, now).unwrap();
    let plan = store.issue("b".into(), true, 0, now).unwrap();
    assert!(store.consume(&old.id, "a", now).is_err());
    assert!(store.consume(&"x".repeat(10000), "b", now).is_err());
    assert!(store.consume(&plan.id, "b", now).is_ok());
    assert!(store.consume(&plan.id, "b", now).is_err());
    let plan = store.issue("b".into(), true, 4, now).unwrap();
    assert!(store.consume(&plan.id, "b", now + TTL).is_err());
    let plan = store.issue("b".into(), true, 4, now).unwrap();
    assert!(store.consume(&plan.id, "changed", now).is_err());
    assert!(store.consume(&plan.id, "b", now).is_err());
}
#[test]
fn unknown_foreign_missing_and_oversized_ownership_plans_never_authorize_repair() {
    for proxy in ["changed", "corrupt", "unavailable", "", "foreign"] {
        assert!(scope(proxy, "none", 0).is_err());
    }
    for route in [
        "changed",
        "missing",
        "unconfirmed",
        "unavailable",
        "unsupported",
        "",
    ] {
        assert!(scope("owned", route, 1).is_err());
    }
    assert!(scope("none", "none", 0).is_err());
    assert!(scope("owned", "none", 1).is_err());
    assert!(scope("owned", "confirmed", 5).is_err());
    assert_eq!(scope("none", "confirmed", 4).unwrap(), (false, 4));
    assert_eq!(
        scope("restored-pending-journal", "none", 0).unwrap(),
        (true, 0)
    );
}
#[test]
fn stale_connected_flag_cannot_hide_a_starting_core_and_poison_fails_closed() {
    let state = AppState::default();
    assert!(require_idle(&state).is_ok());
    *state.starting_runtime.lock().unwrap() = Some(StartingCore {
        pid: 123,
        config_hash: "fixture".into(),
    });
    assert_eq!(require_idle(&state).unwrap_err(), "REPAIR_RUNTIME_PRESENT");
    *state.starting_runtime.lock().unwrap() = None;
    state
        .storage_closed
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(require_idle(&state).is_err());
    state
        .storage_closed
        .store(false, std::sync::atomic::Ordering::Release);
    let _ = std::panic::catch_unwind(|| {
        let _guard = state.connected.lock().unwrap();
        panic!("fixture poison");
    });
    assert_eq!(
        require_idle(&state).unwrap_err(),
        "REPAIR_STATE_UNAVAILABLE"
    );
}
struct Fake {
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    checks: usize,
}
impl Backend for Fake {
    fn check(&mut self) -> Result<(), String> {
        self.checks += 1;
        self.calls.push("check");
        if self.fail
            == Some(if self.checks == 1 {
                "preflight"
            } else {
                "recheck"
            })
        {
            Err("cancelled".into())
        } else {
            Ok(())
        }
    }
    fn proxy(&mut self) -> Result<(), String> {
        self.calls.push("proxy");
        if self.fail == Some("proxy") {
            Err("private PAC".into())
        } else {
            Ok(())
        }
    }
    fn routes(&mut self) -> Result<(), String> {
        self.calls.push("routes");
        if self.fail == Some("routes") {
            Err("private route".into())
        } else {
            Ok(())
        }
    }
    fn verify(&mut self) -> Result<(), String> {
        self.calls.push("verify");
        if self.fail == Some("verify") {
            Err("private path".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn repair_sequence_rechecks_and_reports_partial_failure_without_reenabling_or_claiming_rollback() {
    let plan = RepairPlan {
        id: "a".repeat(48),
        expires_after_ms: 30000,
        restore_proxy: true,
        remove_route_count: 4,
    };
    for fail in [
        None,
        Some("preflight"),
        Some("proxy"),
        Some("recheck"),
        Some("routes"),
        Some("verify"),
    ] {
        let mut backend = Fake {
            calls: vec![],
            fail,
            checks: 0,
        };
        let result = apply(&plan, &mut backend);
        match fail {
            None => {
                result.unwrap();
                assert_eq!(
                    backend.calls,
                    ["check", "proxy", "check", "routes", "verify"]
                );
            }
            Some("preflight") => {
                assert_eq!(backend.calls, ["check"]);
                assert!(result.is_err());
            }
            Some("proxy") => {
                assert_eq!(backend.calls, ["check", "proxy"]);
                assert_eq!(result.unwrap_err(), "REPAIR_PROXY_UNCONFIRMED");
            }
            _ => assert_eq!(result.unwrap_err(), "REPAIR_PARTIAL_ROUTES_UNCONFIRMED"),
        }
    }
    let mut backend = Fake {
        calls: vec![],
        fail: Some("routes"),
        checks: 0,
    };
    assert_eq!(
        apply(
            &RepairPlan {
                restore_proxy: false,
                ..plan
            },
            &mut backend
        )
        .unwrap_err(),
        "REPAIR_ROUTES_UNCONFIRMED"
    );
    assert!(!backend.calls.contains(&"proxy"));
}
#[test]
fn concurrent_confirmation_consumes_exactly_one_plan_and_public_plan_contains_no_private_fingerprint(
) {
    let now = Instant::now();
    let mut plans = RepairPlans::default();
    let plan = plans
        .issue("private snapshot".into(), true, 4, now)
        .unwrap();
    let json = serde_json::to_string(&plan).unwrap();
    assert!(!json.contains("private"));
    assert!(!json.contains("fingerprint"));
    let store = std::sync::Arc::new(Mutex::new(plans));
    let success = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let workers = (0..16)
        .map(|_| {
            let store = store.clone();
            let id = plan.id.clone();
            let success = success.clone();
            std::thread::spawn(move || {
                if store
                    .lock()
                    .unwrap()
                    .consume(&id, "private snapshot", now)
                    .is_ok()
                {
                    success.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(success.load(std::sync::atomic::Ordering::Acquire), 1);
}
