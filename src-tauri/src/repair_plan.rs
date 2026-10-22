//! Explicit, single-use repair consent. This module never owns a global reset.
use super::*;
const TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize)]
pub(crate) struct RepairError {
    code: &'static str,
    category: &'static str,
    retryable: bool,
}
pub(crate) fn public_error(error: &str) -> RepairError {
    let code = match error {
        "REPAIR_BUSY" => "REPAIR_BUSY",
        "REPAIR_STATE_UNAVAILABLE" => "REPAIR_STATE_UNAVAILABLE",
        "REPAIR_RUNTIME_PRESENT" => "REPAIR_RUNTIME_PRESENT",
        "REPAIR_NOT_NEEDED" => "REPAIR_NOT_NEEDED",
        "REPAIR_OWNERSHIP_UNCONFIRMED" => "REPAIR_OWNERSHIP_UNCONFIRMED",
        "REPAIR_PLAN_STALE" => "REPAIR_PLAN_STALE",
        "REPAIR_PLAN_UNAVAILABLE" => "REPAIR_PLAN_UNAVAILABLE",
        "REPAIR_PROXY_UNCONFIRMED" => "REPAIR_PROXY_UNCONFIRMED",
        "REPAIR_PARTIAL_ROUTES_UNCONFIRMED" => "REPAIR_PARTIAL_ROUTES_UNCONFIRMED",
        "REPAIR_ROUTES_UNCONFIRMED" => "REPAIR_ROUTES_UNCONFIRMED",
        "REPAIR_HISTORY_UNAVAILABLE" => "REPAIR_HISTORY_UNAVAILABLE",
        "REPAIR_HISTORY_INVALID" => "REPAIR_HISTORY_INVALID",
        "REPAIR_RECEIPT_UNCONFIRMED" => "REPAIR_RECEIPT_UNCONFIRMED",
        _ => "REPAIR_EXECUTION_UNCONFIRMED",
    };
    RepairError {
        code,
        category: "network",
        retryable: matches!(code, "REPAIR_BUSY" | "REPAIR_PLAN_STALE"),
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RepairPlan {
    id: String,
    expires_after_ms: u64,
    restore_proxy: bool,
    remove_route_count: usize,
}
struct Pending {
    plan: RepairPlan,
    fingerprint: String,
    issued: Instant,
}
#[derive(Default)]
pub(crate) struct RepairPlans {
    pending: Option<Pending>,
}
impl RepairPlans {
    fn issue(
        &mut self,
        fingerprint: String,
        proxy: bool,
        routes: usize,
        now: Instant,
    ) -> Result<RepairPlan, String> {
        let plan = RepairPlan {
            id: crate::durable_state::random_state_id().map_err(|_| "REPAIR_PLAN_UNAVAILABLE")?,
            expires_after_ms: TTL.as_millis() as u64,
            restore_proxy: proxy,
            remove_route_count: routes,
        };
        self.pending = Some(Pending {
            plan: plan.clone(),
            fingerprint,
            issued: now,
        });
        Ok(plan)
    }
    fn consume(&mut self, id: &str, fingerprint: &str, now: Instant) -> Result<RepairPlan, String> {
        if id.len() != 48
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.pending.as_ref().map_or(true, |p| p.plan.id != id)
        {
            return Err("REPAIR_PLAN_STALE".into());
        }
        let pending = self.pending.take().expect("checked plan");
        if now.saturating_duration_since(pending.issued) >= TTL
            || pending.fingerprint != fingerprint
        {
            return Err("REPAIR_PLAN_STALE".into());
        }
        Ok(pending.plan)
    }
}

fn require_idle(state: &AppState) -> Result<(), String> {
    if state
        .storage_closed
        .load(std::sync::atomic::Ordering::Acquire)
        || state
            .stop_requested
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err("REPAIR_BUSY".into());
    }
    // Retained/dead/starting child handles require ordinary lifecycle cleanup;
    // a stale connected=false flag never grants repair permission.
    if *state
        .connected
        .lock()
        .map_err(|_| "REPAIR_STATE_UNAVAILABLE")?
        || state
            .runtime
            .lock()
            .map_err(|_| "REPAIR_STATE_UNAVAILABLE")?
            .is_some()
        || state
            .starting_runtime
            .lock()
            .map_err(|_| "REPAIR_STATE_UNAVAILABLE")?
            .is_some()
    {
        return Err("REPAIR_RUNTIME_PRESENT".into());
    }
    Ok(())
}
fn scope(proxy: &str, route: &str, count: usize) -> Result<(bool, usize), String> {
    if !matches!(
        proxy,
        "none" | "owned" | "prepared" | "restored-pending-journal"
    ) || !matches!(route, "none" | "confirmed")
        || count > 4
        || route == "none" && count != 0
    {
        return Err("REPAIR_OWNERSHIP_UNCONFIRMED".into());
    }
    let proxy = proxy != "none";
    if !proxy && route == "none" {
        return Err("REPAIR_NOT_NEEDED".into());
    }
    Ok((proxy, count))
}
fn observe(app: &AppHandle, state: &AppState) -> Result<(String, bool, usize), String> {
    require_idle(state)?;
    let proxy = windows_proxy_ownership_state(app);
    let (route, routes) = owned_route_summary(app);
    let (restore_proxy, count) = scope(&proxy, &route, routes.len())?;
    let current = current_proxy_snapshot().map_err(|_| "REPAIR_STATE_UNAVAILABLE")?;
    let revision = state
        .operation_machine
        .lock()
        .map_err(|_| "REPAIR_STATE_UNAVAILABLE")?
        .revision;
    // Private proxy/PAC values only contribute to an internal digest. They are
    // never returned in the public plan, receipt or error.
    let fingerprint = sha256_hex_bytes(serde_json::to_string(&json!({
        "revision":revision,"generation":state.operation_generation.load(std::sync::atomic::Ordering::Acquire),
        "proxyOwner":proxy,"routeOwner":route,"routes":routes,
        "proxy":[current.enabled.to_string(),current.server.unwrap_or_default(),current.bypass.unwrap_or_default(),current.auto_config_url.unwrap_or_default(),current.auto_detect.to_string()]
    })).map_err(|_| "REPAIR_STATE_UNAVAILABLE")?.as_bytes());
    Ok((fingerprint, restore_proxy, count))
}

#[tauri::command]
pub(crate) async fn prepare_runtime_repair(app: AppHandle) -> Result<RepairPlan, RepairError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _serialization = state.operation_lock.try_lock().map_err(|_| "REPAIR_BUSY")?;
        let (fingerprint, proxy, count) = observe(&app, &state)?;
        let result = state
            .repair_plans
            .lock()
            .map_err(|_| "REPAIR_STATE_UNAVAILABLE")?
            .issue(fingerprint, proxy, count, Instant::now());
        result
    })
    .await
    .map_err(|_| public_error("REPAIR_PLAN_UNAVAILABLE"))?;
    result.map_err(|e| public_error(&e))
}

trait Backend {
    fn check(&mut self) -> Result<(), String>;
    fn proxy(&mut self) -> Result<(), String>;
    fn routes(&mut self) -> Result<(), String>;
    fn verify(&mut self) -> Result<(), String>;
}
fn apply(plan: &RepairPlan, backend: &mut impl Backend) -> Result<(), String> {
    backend.check()?;
    if plan.restore_proxy {
        backend.proxy().map_err(|_| "REPAIR_PROXY_UNCONFIRMED")?;
    }
    let remaining = (|| {
        backend.check()?;
        // Empty confirmed journals still need their exact journal cleared.
        backend.routes()?;
        backend.verify()
    })();
    remaining.map_err(|_| {
        if plan.restore_proxy {
            "REPAIR_PARTIAL_ROUTES_UNCONFIRMED"
        } else {
            "REPAIR_ROUTES_UNCONFIRMED"
        }
        .into()
    })
}
fn apply_recorded(
    root: &Path,
    plan: &RepairPlan,
    backend: &mut impl Backend,
) -> Result<(), String> {
    crate::repair_history::record(
        root,
        "REPAIR_STARTED",
        plan.restore_proxy,
        plan.remove_route_count,
    )?;
    let result = apply(plan, backend);
    let code = result
        .as_ref()
        .map(|_| "REPAIR_COMPLETED")
        .unwrap_or_else(|e| e.as_str());
    let receipt_code = if matches!(
        code,
        "REPAIR_PROXY_UNCONFIRMED"
            | "REPAIR_PARTIAL_ROUTES_UNCONFIRMED"
            | "REPAIR_ROUTES_UNCONFIRMED"
            | "REPAIR_RUNTIME_PRESENT"
            | "REPAIR_BUSY"
            | "REPAIR_COMPLETED"
    ) {
        code
    } else {
        "REPAIR_EXECUTION_UNCONFIRMED"
    };
    crate::repair_history::record(
        root,
        receipt_code,
        plan.restore_proxy,
        plan.remove_route_count,
    )
    .map_err(|_| "REPAIR_RECEIPT_UNCONFIRMED")?;
    result
}
pub(crate) fn execute(app: AppHandle, plan_id: String) -> Result<RuntimeStatus, String> {
    let state = app.state::<AppState>();
    let serialization = state.operation_lock.try_lock().map_err(|_| "REPAIR_BUSY")?;
    let (fingerprint, _, _) = observe(&app, &state)?;
    let plan = state
        .repair_plans
        .lock()
        .map_err(|_| "REPAIR_STATE_UNAVAILABLE")?
        .consume(&plan_id, &fingerprint, Instant::now())?;
    let mut lease = adopt_runtime_operation(
        &state,
        serialization,
        "repair-owned-state",
        Duration::from_secs(30),
    )?;
    struct Native<'a, 'b> {
        app: &'a AppHandle,
        state: &'a AppState,
        lease: &'a OperationLease<'b>,
    }
    impl Backend for Native<'_, '_> {
        fn check(&mut self) -> Result<(), String> {
            self.lease.check()?;
            require_idle(self.state)
        }
        fn proxy(&mut self) -> Result<(), String> {
            restore_owned_windows_proxy(self.app).map(|_| ())
        }
        fn routes(&mut self) -> Result<(), String> {
            cleanup_tun_routes_for_app(self.app, TUN_INTERFACE_NAME, &[])
        }
        fn verify(&mut self) -> Result<(), String> {
            self.check()?;
            if windows_proxy_ownership_state(self.app) != "none"
                || owned_route_summary(self.app).0 != "none"
            {
                return Err("REPAIR_READBACK_UNCONFIRMED".into());
            }
            Ok(())
        }
    }
    let history_root = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "REPAIR_HISTORY_UNAVAILABLE")?;
    // Durable intent before effects. A failure preserves the old receipt file
    // and prevents repair; a later missing terminal receipt means unknown.
    let result = apply_recorded(
        &history_root,
        &plan,
        &mut Native {
            app: &app,
            state: &state,
            lease: &lease,
        },
    );
    let _ = append_runtime_event(
        &app,
        result
            .as_ref()
            .map(|_| "REPAIR_COMPLETED")
            .unwrap_or_else(|e| e.as_str()),
    );
    result?;
    lease.commit();
    drop(lease);
    refresh_tray_menu(&app);
    Ok(read_runtime_status(&app, state))
}

#[cfg(test)]
mod tests;
