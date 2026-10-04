use super::*;

pub(crate) fn terminate_child_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    if let Ok(Some(status)) = child.try_wait() {
        return Some(status);
    }
    // Child::kill uses the retained Windows process HANDLE. Never taskkill a
    // numeric PID after exit: Windows may already have reused that PID.
    let _ = child.kill();
    let started_at = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if started_at.elapsed() >= timeout {
                    break;
                }
                std::thread::sleep(Duration::from_millis(35));
            }
            Err(_) => return None,
        }
    }

    let _ = child.kill();
    let forced_started_at = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if forced_started_at.elapsed() >= Duration::from_secs(2) {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(35));
            }
            Err(_) => return None,
        }
    }
}

pub(crate) struct PendingXray {
    child: Option<OwnedXrayProcess>,
    app: AppHandle,
    config_path: PathBuf,
    network_mode: String,
    tun_server_ips: Vec<String>,
}
impl PendingXray {
    pub(crate) fn new(
        child: OwnedXrayProcess,
        app: AppHandle,
        config_path: PathBuf,
        network_mode: String,
        tun_server_ips: Vec<String>,
    ) -> Self {
        Self {
            child: Some(child),
            app,
            config_path,
            network_mode,
            tun_server_ips,
        }
    }
    pub(crate) fn commit(mut self) -> OwnedXrayProcess {
        self.child.take().expect("pending child owned")
    }
}
impl std::ops::Deref for PendingXray {
    type Target = OwnedXrayProcess;
    fn deref(&self) -> &OwnedXrayProcess {
        self.child.as_ref().expect("pending child owned")
    }
}
impl std::ops::DerefMut for PendingXray {
    fn deref_mut(&mut self) -> &mut OwnedXrayProcess {
        self.child.as_mut().expect("pending child owned")
    }
}
impl Drop for PendingXray {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let pid = child.id();
            let _ = terminate_child_with_timeout(child, Duration::from_secs(3));
            child.release_integrity();
            let state = self.app.state::<AppState>();
            clear_starting_runtime(&state, pid);
            if self.network_mode == "tun" {
                let _ =
                    cleanup_tun_routes_for_app(&self.app, TUN_INTERFACE_NAME, &self.tun_server_ips);
            }
            let _ = restore_saved_proxy_state(&self.app, &state, "pending_start_failed");
            let _ = fs::remove_file(&self.config_path);
        }
    }
}

pub(crate) const MAX_XRAY_SELF_RESTARTS: u8 = 3;
pub(crate) const XRAY_SELF_RESTART_READY_TIMEOUT: Duration = Duration::from_secs(14);

pub(crate) fn spawn_xray_runtime_child(
    core_path: &Path,
    config_path: &Path,
    log_path: &Path,
    expected_config_hash: &str,
) -> Result<OwnedXrayProcess, String> {
    // Validate the sink before starting a child. Pipe draining keeps disk and
    // capture memory bounded independently of Xray's internal file logger.
    append_bounded_log(log_path, "[XRAY] runtime start")?;

    let integrity = prepare_core_launch(core_path, Some((config_path, expected_config_hash)))?;
    let core_path = integrity.core.as_path();
    let config_path = integrity
        .config
        .as_deref()
        .ok_or("CONFIG_PROVENANCE_MISSING")?;
    let core_working_dir = core_path.parent().ok_or_else(|| {
        "Не удалось определить рабочую папку Xray-core для запуска runtime.".to_string()
    })?;
    let config_dir = config_path.parent().unwrap_or(core_working_dir);

    let mut command = Command::new(core_path);
    command
        .current_dir(core_working_dir)
        .env("XRAY_LOCATION_ASSET", core_working_dir)
        .env("XRAY_LOCATION_CONFIG", config_dir)
        .arg("run")
        .arg("-config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_child_console(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format_xray_spawn_error(&error, core_path))?;
    let stdout = child.stdout.take().ok_or("STDOUT_PIPE_MISSING")?;
    let stderr = child.stderr.take().ok_or("STDERR_PIPE_MISSING")?;
    let owned = OwnedXrayProcess::attach(child)?.with_integrity(integrity);
    drain_runtime_log(stdout, log_path.to_path_buf());
    drain_runtime_log(stderr, log_path.to_path_buf());
    Ok(owned)
}

fn controlled_restart_delay(attempt: u8) -> Duration {
    match attempt {
        0 | 1 => Duration::from_millis(450),
        2 => Duration::from_millis(900),
        _ => Duration::from_millis(1500),
    }
}

pub(crate) fn acquire_operation_lock<'a>(
    state: &'a tauri::State<AppState>,
    timeout: Duration,
    context: &str,
) -> Result<OperationLease<'a>, String> {
    begin_runtime_operation(state, timeout, context, Duration::from_secs(45))
}

pub(crate) fn remember_starting_runtime(state: &tauri::State<AppState>, starting: StartingCore) {
    if let Ok(mut guard) = state.starting_runtime.lock() {
        *guard = Some(starting);
    }
}

pub(crate) fn clear_starting_runtime(state: &tauri::State<AppState>, pid: u32) {
    if let Ok(mut guard) = state.starting_runtime.lock() {
        if guard.as_ref().map(|item| item.pid) == Some(pid) {
            *guard = None;
        }
    }
}

pub(crate) fn stop_starting_runtime(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    reason: &str,
) -> bool {
    let _ = (app, reason);
    // PendingXray cancels its retained child handle; never terminate a numeric PID.
    state
        .starting_runtime
        .lock()
        .map(|mut s| s.take().is_some())
        .unwrap_or(false)
}

pub(crate) fn stop_managed_or_starting_runtime(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    restore_proxy: bool,
    reason: &str,
) -> Result<(), String> {
    let stopped_starting = stop_starting_runtime(app, state, reason);
    stop_existing_runtime(app, state, restore_proxy)?;

    if stopped_starting && restore_proxy {
        let _ = restore_saved_proxy_state(app, state, reason);
    }

    Ok(())
}

pub(crate) fn stop_existing_runtime(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    restore_proxy: bool,
) -> Result<(), String> {
    let mut cleanup_errors = Vec::new();
    let runtime_to_stop = {
        let mut runtime_guard = state
            .runtime
            .lock()
            .map_err(|_| "Не удалось получить доступ к runtime состоянию.".to_string())?;
        runtime_guard.take()
    };

    if let Some(mut runtime) = runtime_to_stop {
        let shutdown_timeout = if restore_proxy {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(1200)
        };
        let _ = append_runtime_event(
            app,
            if restore_proxy {
                "Останавливаем предыдущий Xray runtime."
            } else {
                "Быстро останавливаем предыдущий Xray runtime для мягкого переключения сервера."
            },
        );
        let status = terminate_child_with_timeout(&mut runtime.child, shutdown_timeout);
        if status.is_none() {
            if let Ok(mut guard) = state.runtime.lock() {
                *guard = Some(runtime);
            }
            return Err("PROCESS_STOP_UNCONFIRMED: child termination was not confirmed.".into());
        }

        if runtime.network_mode == "tun" {
            if let Err(error) = cleanup_tun_routes_for_app(
                app,
                runtime
                    .tun_interface_name
                    .as_deref()
                    .unwrap_or(TUN_INTERFACE_NAME),
                &runtime.tun_server_ips,
            ) {
                cleanup_errors.push(error);
            }
        }

        // A failed cleanup cannot continue the reconnect. The old child is
        // confirmed stopped here, so its proxy journal must be restored too.
        if restore_proxy || !cleanup_errors.is_empty() {
            if let Err(error) = restore_saved_proxy_state(app, state, "runtime_stop") {
                cleanup_errors.push(error);
            }
        } else {
            let _ = append_runtime_event(app, "Proxy backup сохранён: при мягком переподключении системный proxy не сбрасываем между старым и новым Xray.");
        }
        runtime.child.release_integrity();
        let _ = fs::remove_file(Path::new(&runtime.config_path));

        if let Some(code) = status.and_then(|item| item.code()) {
            if let Ok(mut exit_guard) = state.last_exit_code.lock() {
                *exit_guard = Some(code);
            }
        }
    }

    if let Ok(mut guard) = state.connected.lock() {
        *guard = false;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = None;
    }

    if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(format!("CLEANUP_INCOMPLETE: {}", cleanup_errors.join("; ")))
    }
}

pub(crate) fn stop_runtime_orphans_for_app(
    app: &AppHandle,
    _state: &tauri::State<AppState>,
    reason: &str,
) -> bool {
    // Legacy processes have no retained ownership handle. Never infer it from a path.
    let busy_ports = runtime_busy_ports();
    if !busy_ports.is_empty() {
        let _ = append_runtime_event(
            app,
            &format!(
                "Unowned runtime ports occupied ({reason}): {}. No process terminated.",
                format_busy_runtime_ports(&busy_ports)
            ),
        );
    }
    false
}

pub(crate) fn cleanup_application(app: &AppHandle, reason: &str) {
    let _ = append_runtime_event(app, &format!("Запущен cleanup приложения: {reason}."));
    if let Err(error) = request_disconnect_blocking(app.clone()) {
        let _ = append_runtime_event(app, &format!("Cleanup не подтверждён ({reason}): {error}"));
    }
    refresh_tray_menu(app);
}

pub(crate) fn normalize_socket_host(host: &str) -> String {
    host.trim().trim_matches('[').trim_matches(']').to_string()
}

pub(crate) fn format_endpoint_for_display(host: &str, port: u16) -> String {
    let normalized = normalize_socket_host(host);
    if normalized.contains(':') {
        format!("[{normalized}]:{port}")
    } else {
        format!("{normalized}:{port}")
    }
}

pub(crate) fn resolve_socket_addresses(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, String> {
    let normalized = normalize_socket_host(host);
    if normalized.is_empty() || normalized.len() > 253 || normalized.contains('\0') || port == 0 {
        return Err("Invalid socket endpoint".into());
    }
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    static WORKERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if WORKERS
        .fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |n| (n < 4).then_some(n + 1),
        )
        .is_err()
    {
        return Err("DNS_BUSY: bounded resolver workers exhausted".into());
    }
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        struct Worker;
        impl Drop for Worker {
            fn drop(&mut self) {
                WORKERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        let _worker = Worker;
        let result = (normalized.as_str(), port)
            .to_socket_addrs()
            .map(|items| items.take(65).collect::<Vec<_>>())
            .map_err(|_| "DNS resolution failed".to_string());
        let _ = sender.send(result);
    });
    let mut addresses = receiver
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| "DNS_TIMEOUT: resolution deadline".to_string())??;
    if addresses.is_empty() || addresses.len() > 64 {
        return Err("Invalid DNS result size".into());
    }
    addresses.sort_by_key(|address| if address.is_ipv4() { 0 } else { 1 });
    addresses.dedup();
    Ok(addresses)
}

pub(crate) fn tcp_port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms);

    resolve_socket_addresses(host, port)
        .map(|addresses| {
            addresses
                .iter()
                .any(|socket| TcpStream::connect_timeout(socket, timeout).is_ok())
        })
        .unwrap_or(false)
}

pub(crate) fn runtime_busy_ports() -> Vec<u16> {
    let mut busy_ports = Vec::new();

    if tcp_port_open("127.0.0.1", SOCKS_PORT, 350) {
        busy_ports.push(SOCKS_PORT);
    }

    if tcp_port_open("127.0.0.1", HTTP_PORT, 350) {
        busy_ports.push(HTTP_PORT);
    }

    if tcp_port_open("127.0.0.1", XRAY_API_PORT, 350) {
        busy_ports.push(XRAY_API_PORT);
    }

    busy_ports
}

pub(crate) fn format_busy_runtime_ports(busy_ports: &[u16]) -> String {
    busy_ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn ensure_runtime_ports_available() -> Result<(), String> {
    let busy_ports = runtime_busy_ports();

    if busy_ports.is_empty() {
        return Ok(());
    }

    Err(format!(
        "Локальные порты VKarmani уже заняты: {}. Закройте другой VPN/proxy-клиент или перезапустите VKarmani.",
        format_busy_runtime_ports(&busy_ports)
    ))
}

pub(crate) fn wait_for_runtime_ports_release(timeout: Duration) -> Result<(), String> {
    let started_at = Instant::now();
    loop {
        let busy_ports = runtime_busy_ports();
        if busy_ports.is_empty() {
            return Ok(());
        }

        if started_at.elapsed() >= timeout {
            return Err(format!(
                "После остановки Xray локальные порты не освободились за {} секунд: {}. Старый процесс мог зависнуть, перезапустите VKarmani или завершите xray.exe в диспетчере задач.",
                timeout.as_secs(),
                format_busy_runtime_ports(&busy_ports)
            ));
        }

        std::thread::sleep(Duration::from_millis(120));
    }
}

#[cfg(target_os = "windows")]
pub(crate) const POWERSHELL_COMMAND_TIMEOUT: Duration = Duration::from_secs(12);

#[cfg(target_os = "windows")]
pub(crate) fn run_powershell_command(command: Command, context: &str) -> Result<String, String> {
    run_command_with_timeout(command, POWERSHELL_COMMAND_TIMEOUT, context)
}

#[cfg(target_os = "windows")]
pub(crate) fn run_powershell(script: &str) -> Result<String, String> {
    let mut command = Command::new(system_program("powershell")?);
    let utf8_script = format!("[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding; {script}");
    command.args(["-NoProfile", "-NonInteractive", "-Command", &utf8_script]);
    run_powershell_command(command, "script")
}

pub(crate) fn current_proxy_snapshot() -> Result<ProxyStatus, String> {
    read_wininet_settings().map(|settings| settings.status())
}

#[cfg(test)]
pub(crate) fn proxy_status_from_registry_json(
    raw: &str,
    method: &str,
) -> Result<ProxyStatus, String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|_| "Некорректный legacy proxy snapshot".to_string())?;
    let text = |key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    Ok(ProxyStatus {
        enabled: value
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        server: text("server"),
        bypass: text("bypass"),
        method: method.into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
        auto_config_url: None,
        auto_detect: false,
    })
}

pub(crate) fn proxy_snapshot_points_to_runtime(snapshot: &ProxyStatus) -> bool {
    snapshot.enabled
        && snapshot.server.as_deref()
            == Some(format!("http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT}").as_str())
}

pub(crate) fn restore_saved_proxy_state(
    app: &AppHandle,
    _state: &tauri::State<AppState>,
    reason: &str,
) -> Result<Option<ProxyStatus>, String> {
    let restored = restore_owned_windows_proxy(app)?;
    if restored.is_some() {
        let _ = append_runtime_event(
            app,
            &format!("Owned Windows proxy/PAC/bypass/autodetect restored ({reason})."),
        );
    }
    Ok(restored)
}

pub(crate) fn recover_orphaned_system_proxy(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    reason: &str,
) -> Result<Option<ProxyStatus>, String> {
    // Only a durable ownership journal authorizes recovery. Legacy endpoint
    // heuristics/old incomplete plaintext snapshots cannot prove ownership.
    restore_saved_proxy_state(app, state, reason)
}

#[cfg(target_os = "windows")]
pub(crate) fn is_process_elevated() -> Result<bool, String> {
    use windows_sys::Win32::{Foundation::CloseHandle, Security::*, System::Threading::*};
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("TOKEN_QUERY_FAILED".into());
    }
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut size = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut size,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err("TOKEN_ELEVATION_FAILED".into());
    }
    Ok(elevation.TokenIsElevated != 0)
}
#[cfg(not(target_os = "windows"))]
pub(crate) fn is_process_elevated() -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "windows")]
pub(crate) fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn wait_for_restarted_xray_ready(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    child: &mut Child,
    log_path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let started_at = Instant::now();

    loop {
        check_current_operation(state)?;
        if let Some(status) = child.try_wait().map_err(|error| {
            format!("Не удалось проверить статус перезапущенного Xray-core: {error}")
        })? {
            let code = status.code();
            if let Ok(mut exit_guard) = state.last_exit_code.lock() {
                *exit_guard = code;
            }

            let log_excerpt = read_runtime_log_excerpt(log_path, 8).join(" | ");
            return Err(if log_excerpt.is_empty() {
                format!(
                    "Xray завершился сразу после автоматического перезапуска. Exit code: {:?}.",
                    code
                )
            } else {
                format!(
                    "Xray завершился сразу после автоматического перезапуска. Exit code: {:?}. Последние строки xray-runtime.log: {}",
                    code,
                    log_excerpt
                )
            });
        }

        let http_ready = tcp_port_open("127.0.0.1", HTTP_PORT, 90);
        let socks_ready = tcp_port_open("127.0.0.1", SOCKS_PORT, 90);
        let api_ready = tcp_port_open("127.0.0.1", XRAY_API_PORT, 90);

        if http_ready && socks_ready && api_ready {
            let _ = append_runtime_event(
                app,
                &format!("Автоматически перезапущенный Xray снова готов: http={http_ready} socks={socks_ready} api={api_ready}."),
            );
            return Ok(());
        }

        if started_at.elapsed() >= timeout {
            let log_excerpt = read_runtime_log_excerpt(log_path, 8).join(" | ");
            let details = if log_excerpt.is_empty() {
                "Лог Xray пока пуст.".to_string()
            } else {
                format!("Последние строки xray-runtime.log: {log_excerpt}")
            };
            return Err(format!(
                "Xray был перезапущен, но локальные порты не стали готовы за {} секунд. {details}",
                timeout.as_secs()
            ));
        }

        std::thread::sleep(Duration::from_millis(110));
    }
}

fn try_self_restart_xray_runtime(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    mut runtime: ManagedCore,
    exit_code: Option<i32>,
) -> Result<(), Box<(ManagedCore, String)>> {
    if runtime.self_restart_count >= MAX_XRAY_SELF_RESTARTS {
        let restart_count = runtime.self_restart_count;
        return Err(Box::new((
            runtime,
            format!(
                "лимит автоматических перезапусков исчерпан: {}/{}",
                restart_count, MAX_XRAY_SELF_RESTARTS
            ),
        )));
    }

    let core_path = PathBuf::from(&runtime.core_path);
    let config_path = PathBuf::from(&runtime.config_path);
    let log_path = PathBuf::from(&runtime.log_path);

    if !core_path.exists() {
        return Err(Box::new((
            runtime,
            format!(
                "xray.exe не найден для автоматического перезапуска: {}",
                core_path.display()
            ),
        )));
    }
    if !config_path.exists() {
        return Err(Box::new((
            runtime,
            format!(
                "runtime config уже удалён, перезапуск невозможен: {}",
                config_path.display()
            ),
        )));
    }

    let attempt = runtime.self_restart_count.saturating_add(1);
    let delay = controlled_restart_delay(attempt);
    let _ = append_runtime_event(
        app,
        &format!(
            "Xray завершился во время активной сессии (exit={:?}). Выполняю контролируемый автоматический перезапуск {}/{} через {} мс без сброса пользовательского подключения.",
            exit_code,
            attempt,
            MAX_XRAY_SELF_RESTARTS,
            delay.as_millis()
        ),
    );
    std::thread::sleep(delay);

    if let Err(error) = check_current_operation(state) {
        return Err(Box::new((runtime, error)));
    }
    if state
        .stop_requested
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(Box::new((
            runtime,
            "OPERATION_CANCELLED: ожидается отключение.".into(),
        )));
    }

    let mut child =
        match spawn_xray_runtime_child(&core_path, &config_path, &log_path, &runtime.config_hash) {
            Ok(child) => child,
            Err(error) => return Err(Box::new((runtime, error))),
        };

    if let Err(error) = wait_for_restarted_xray_ready(
        app,
        state,
        &mut child,
        &log_path,
        XRAY_SELF_RESTART_READY_TIMEOUT,
    ) {
        let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
        return Err(Box::new((runtime, error)));
    }

    if runtime.network_mode == "tun" {
        let tun_name = runtime
            .tun_interface_name
            .clone()
            .unwrap_or_else(|| TUN_INTERFACE_NAME.to_string());
        if let Err(error) = configure_tun_routes(app, &tun_name, &runtime.tun_server_ips) {
            let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
            return Err(Box::new((
                runtime,
                format!("Xray перезапущен, но TUN маршруты не восстановились: {error}"),
            )));
        }
        std::thread::sleep(Duration::from_millis(250));
        let _ = append_runtime_event(
            app,
            "TUN маршруты повторно применены после автоматического перезапуска Xray.",
        );
    }

    if let Err(error) = check_current_operation(state) {
        let _ = terminate_child_with_timeout(&mut child, Duration::from_secs(3));
        return Err(Box::new((runtime, error)));
    }
    runtime.child = child;
    runtime.started_at = unix_now_string();
    runtime.self_restart_count = attempt;
    runtime.last_self_restart_at = Some(unix_now_string());

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        *runtime_guard = Some(runtime);
    }
    if let Ok(mut connected_guard) = state.connected.lock() {
        *connected_guard = true;
    }
    if let Ok(mut exit_guard) = state.last_exit_code.lock() {
        *exit_guard = None;
    }

    let _ = append_runtime_event(
        app,
        &format!(
            "Xray успешно восстановлен автоматическим перезапуском {}/{}. Сессия оставлена активной.",
            attempt,
            MAX_XRAY_SELF_RESTARTS
        ),
    );
    refresh_tray_menu(app);
    Ok(())
}

fn finalize_unexpected_xray_exit(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    mut runtime: ManagedCore,
    exit_code: Option<i32>,
    reason: &str,
) {
    if runtime.network_mode == "tun" {
        let _ = cleanup_tun_routes_for_app(
            app,
            runtime
                .tun_interface_name
                .as_deref()
                .unwrap_or(TUN_INTERFACE_NAME),
            &runtime.tun_server_ips,
        );
    }
    runtime.child.release_integrity();
    let _ = fs::remove_file(Path::new(&runtime.config_path));

    if let Ok(mut exit_guard) = state.last_exit_code.lock() {
        *exit_guard = exit_code;
    }
    if let Ok(mut guard) = state.connected.lock() {
        *guard = false;
    }
    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = None;
    }

    let _ = append_runtime_event(
        app,
        &format!(
            "Xray-core завершился во время работы. Exit code: {:?}. Автовосстановление не выполнено: {}",
            exit_code,
            reason
        ),
    );
    let _ = restore_saved_proxy_state(app, state, "xray_exit");
    let _ = app.emit("vkarmani://native-disconnect", "stopped");
    refresh_tray_menu(app);
}

pub(crate) fn sync_runtime_liveness(app: &AppHandle, state: &tauri::State<AppState>) {
    if state
        .stop_requested
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return;
    }
    // Runtime commands own the same serialization lock. A status poll must
    // never take a half-stopped child and resurrect it alongside disconnect.
    let Ok(serialization) = state.operation_lock.try_lock() else {
        return;
    };
    let mut exited_runtime: Option<(ManagedCore, Option<i32>)> = None;

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        if let Some(runtime) = runtime_guard.as_mut() {
            match runtime.child.try_wait() {
                Ok(Some(status)) => {
                    exited_runtime = runtime_guard.take().map(|runtime| (runtime, status.code()));
                }
                Ok(None) => {
                    if runtime.self_restart_count > 0 {
                        let stable_for_secs = runtime
                            .last_self_restart_at
                            .as_deref()
                            .and_then(|value| value.parse::<u64>().ok())
                            .map(|last_restart| {
                                unix_timestamp_seconds().saturating_sub(last_restart)
                            })
                            .unwrap_or_default();
                        if stable_for_secs >= 900 {
                            runtime.self_restart_count = 0;
                            runtime.last_self_restart_at = None;
                            let _ = append_runtime_event(
                                app,
                                "Xray стабильно работает после автоперезапуска больше 15 минут; счётчик защитных перезапусков сброшен.",
                            );
                        }
                    }
                }
                Err(error) => {
                    let _ = append_runtime_event(
                        app,
                        &format!("Не удалось проверить состояние Xray-core: {error}"),
                    );
                }
            }
        }
    }

    let Some((runtime, exit_code)) = exited_runtime else {
        return;
    };

    let Ok(mut operation) =
        adopt_runtime_operation(state, serialization, "reconnect", Duration::from_secs(30))
    else {
        return;
    };

    match try_self_restart_xray_runtime(app, state, runtime, exit_code) {
        Ok(()) => {
            operation.commit();
        }
        Err(failure) => {
            let (runtime, error) = *failure;
            finalize_unexpected_xray_exit(app, state, runtime, exit_code, &error);
        }
    }
}

pub(crate) fn start_runtime_watchdog(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last_orphan_sweep = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let state = app.state::<AppState>();
            sync_runtime_liveness(&app, &state);

            if last_orphan_sweep.elapsed() < Duration::from_secs(8) {
                continue;
            }
            last_orphan_sweep = Instant::now();

            let has_managed_runtime = state
                .runtime
                .lock()
                .map(|guard| guard.is_some())
                .unwrap_or(false);
            let has_starting_runtime = state
                .starting_runtime
                .lock()
                .map(|guard| guard.is_some())
                .unwrap_or(false);

            // Если приложение уже считает VPN остановленным, но локальные порты Xray
            // всё ещё заняты, значит остался зависший orphan-процесс. Добиваем только
            // процессы нашего core/config из runtime-папки, чужие VPN-клиенты не трогаем.
            if !has_managed_runtime && !has_starting_runtime && !runtime_busy_ports().is_empty() {
                let Ok(_serialization) = state.operation_lock.try_lock() else {
                    continue;
                };
                if state
                    .runtime
                    .lock()
                    .map(|runtime| runtime.is_some())
                    .unwrap_or(true)
                    || state
                        .starting_runtime
                        .lock()
                        .map(|runtime| runtime.is_some())
                        .unwrap_or(true)
                {
                    continue;
                }
                if stop_runtime_orphans_for_app(&app, &state, "watchdog_orphan_ports") {
                    let _ = restore_saved_proxy_state(&app, &state, "watchdog_orphan_ports");
                    let _ = app.emit("vkarmani://native-disconnect", "stopped");
                    refresh_tray_menu(&app);
                }
            }
        }
    });
}
