use super::*;

pub(crate) const TRAY_ID: &str = "vkarmani-main-tray";

pub(crate) fn build_tray_menu(
    app: &AppHandle,
    connected: bool,
    proxy_active: bool,
    authorized: bool,
    update_available: bool,
    update_busy: bool,
) -> tauri::Result<Menu<tauri::Wry>> {
    let show_item = MenuItem::with_id(app, "show", "Открыть VKarmani", true, None::<&str>)?;
    let connect_item =
        MenuItem::with_id(app, "connect", "Быстрое подключение", true, None::<&str>)?;
    let disconnect_item = MenuItem::with_id(app, "disconnect", "Отключиться", true, None::<&str>)?;
    let update_label = if update_busy {
        "Обновление: выполняется…"
    } else if update_available {
        "Установить обновление"
    } else {
        "Проверить обновления"
    };
    let update_item = MenuItem::with_id(
        app,
        "update_action",
        update_label,
        !update_busy,
        None::<&str>,
    )?;
    let restart_app_item = MenuItem::with_id(
        app,
        "restart_app",
        "Перезапустить программу",
        true,
        None::<&str>,
    )?;
    let restart_proxy_item = MenuItem::with_id(
        app,
        "restart_proxy",
        "Перезапустить прокси",
        true,
        None::<&str>,
    )?;
    let logout_item = MenuItem::with_id(app, "logout", "Выйти из ЛК", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;

    let mut items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![&show_item, &update_item];

    if authorized && !connected {
        items.push(&connect_item);
    }

    if connected {
        items.push(&disconnect_item);
    }

    if proxy_active {
        items.push(&restart_proxy_item);
    }

    items.push(&restart_app_item);

    if authorized {
        items.push(&logout_item);
    }

    items.push(&quit_item);

    Menu::with_items(app, &items)
}

pub(crate) fn tray_runtime_flags(app: &AppHandle) -> (bool, bool, bool, bool, bool) {
    let state = app.state::<AppState>();
    let connected = state
        .runtime
        .lock()
        .map(|runtime| runtime.is_some())
        .unwrap_or(false);

    let proxy_active = current_proxy_snapshot()
        .map(|snapshot| proxy_snapshot_points_to_runtime(&snapshot))
        .unwrap_or(false);

    let authorized = state
        .session_authorized
        .lock()
        .map(|value| *value)
        .unwrap_or(false);

    let update_available = state
        .tray_update_available
        .lock()
        .map(|value| *value)
        .unwrap_or(false);

    let update_busy = state
        .tray_update_busy
        .lock()
        .map(|value| *value)
        .unwrap_or(false);

    (
        connected,
        proxy_active,
        authorized,
        update_available,
        update_busy,
    )
}

pub(crate) fn refresh_tray_menu(app: &AppHandle) {
    if startup_is_safe(app) {
        return;
    }
    let (connected, proxy_active, authorized, update_available, update_busy) =
        tray_runtime_flags(app);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        match build_tray_menu(
            app,
            connected,
            proxy_active,
            authorized,
            update_available,
            update_busy,
        ) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(error) => {
                let _ =
                    append_interface_event(app, &format!("Не удалось обновить меню трея: {error}"));
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    crash_receipts::install_crash_hook();
    crash_receipts::crash_phase(crash_receipts::CrashPhase::Builder);
    let environment = match crate::elevation::startup_environment() {
        Ok(environment) => environment,
        Err(failure) => {
            eprintln!("ELEVATION_STARTUP_ABORTED {}", failure.code);
            return;
        }
    };
    // Debug and release share AppData, ports and TUN resources. Both must own
    // the same instance lock. Pending elevation waits before this builder.
    let builder =
        tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            reveal_main_window(app);
            let _ = app.emit("vkarmani://tray-action", "show");
        }));

    builder
        .manage(environment)
        .manage(AppState::default())
        .setup(|app| {
            *app.state::<AppState>().startup.lock().map_err(|_|"STARTUP_GUARD_UNAVAILABLE")? = StartupSupervisor::initialize(app.handle());
            if startup_is_safe(app.handle()) {
                // No user-state load/migration, recovery, updater or watchdog.
                // Recovery mode owns no runtime and can quit without a v2 ACK.
                reveal_main_window(app.handle());
                return Ok(());
            }
            let _ = interface_logs_dir(app.handle());
            let _ = routing_logs_dir(app.handle());
            let _ = ensure_log_tree(app.handle());
            crash_receipts::configure_crash_sink(app.handle());
            crash_receipts::crash_phase(crash_receipts::CrashPhase::StartupRecovery);
            let _ = cleanup_tun_routes_for_app(app.handle(), TUN_INTERFACE_NAME, &[]);
            let _ = cleanup_runtime_config_files(app.handle());
            let state = app.state::<AppState>();
            let _ = recover_orphaned_system_proxy(app.handle(), &state, "startup_recovery");
            start_runtime_watchdog(app.handle().clone());
            let _ = append_interface_event(
                app.handle(),
                "Приложение запущено. Структура логов проверена.",
            );
            let _ = append_runtime_event(
                app.handle(),
                "Routing/runtime лог инициализирован. Ожидание действий пользователя.",
            );
            crash_receipts::crash_phase(crash_receipts::CrashPhase::Tray);
            let menu = build_tray_menu(app.handle(), false, false, false, false, false)?;

            let mut tray_builder = TrayIconBuilder::with_id(TRAY_ID);
            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }

            tray_builder
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        let _ = append_interface_event(app, "Tray: открыть окно.");
                        reveal_main_window(app);
                        let _ = app.emit("vkarmani://tray-action", "show");
                    }
                    "connect" => {
                        let _ = append_interface_event(app, "Tray: быстрое подключение.");
                        reveal_main_window(app);
                        let _ = app.emit("vkarmani://tray-action", "connect");
                    }
                    "disconnect" => {
                        let _ = append_interface_event(app, "Tray: отключение.");
                        reveal_main_window(app);
                        let _ = app.emit("vkarmani://tray-action", "disconnect");
                    }
                    "update_action" => {
                        let update_available = app
                            .state::<AppState>()
                            .tray_update_available
                            .lock()
                            .map(|value| *value)
                            .unwrap_or(false);
                        let _ = append_interface_event(
                            app,
                            if update_available {
                                "Tray: установка найденного обновления."
                            } else {
                                "Tray: проверка наличия обновлений."
                            },
                        );
                        reveal_main_window(app);
                        let _ = app.emit(
                            "vkarmani://tray-action",
                            if update_available {
                                "install_update"
                            } else {
                                "check_updates"
                            },
                        );
                    }
                    "restart_app" => {
                        let _ = append_interface_event(app, "Tray: перезапуск приложения.");
                        if let Err(error) = restart_application(app.clone()) {
                            let _ = append_interface_event(
                                app,
                                &format!("Tray restart отменён: {error}"),
                            );
                            reveal_main_window(app);
                        }
                    }
                    "restart_proxy" => {
                        let _ = append_interface_event(app, "Tray: перезапуск proxy.");
                        reveal_main_window(app);
                        let _ = app.emit("vkarmani://tray-action", "restart_proxy");
                    }
                    "logout" => {
                        let _ = append_interface_event(app, "Tray: выход из ЛК.");
                        reveal_main_window(app);
                        let _ = app.emit("vkarmani://tray-action", "logout");
                    }
                    "quit" => {
                        let _ = append_interface_event(app, "Tray: выход из приложения.");
                        if begin_state_handoff(app, HandoffAction::Quit).is_err() {
                            reveal_main_window(app);
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        reveal_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            reveal_main_window(app.handle());
            let _ = append_interface_event(app.handle(), "Главное окно активировано при запуске.");

            crash_receipts::crash_phase(crash_receipts::CrashPhase::Updater);
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
            crash_receipts::crash_phase(crash_receipts::CrashPhase::Runtime);
            Ok(())
        })
        .invoke_handler(|invoke| {
            let app=invoke.message.webview().app_handle().clone();
            if startup_commands_blocked(&app) && !startup_command_allowed(invoke.message.command()) {
                invoke.resolver.reject(serde_json::json!({"code":"STARTUP_SAFE_MODE_REQUIRED","category":"startup","retryable":false}));
                return true;
            }
            let handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![
            startup_status,
            startup_admit_app,
            startup_acknowledge_ready,
            startup_retry_next_launch,
            startup_exit,
            bootstrap_info,
            load_state_snapshot,
            commit_state_patch,
            recover_state_snapshot,
            export_state_legacy,
            acknowledge_state_handoff,
            cancel_state_handoff,
            seal_state_for_update,
            approve_state_update_exit,
            save_access_key_secure,
            load_access_key_secure,
            clear_access_key_secure,
            save_client_state_value,
            load_client_state_value,
            clear_client_state_value,
            save_sensitive_client_state_value,
            load_sensitive_client_state_value,
            clear_sensitive_client_state_value,
            runtime_status,
            diagnostics_snapshot,
            runtime_observation,
            set_session_authorized,
            set_tray_update_state,
            request_connect,
            request_disconnect,
            rollback_failed_connect,
            cache_profile_sync,
            write_interface_log,
            write_routing_log,
            request_show,
            window_minimize,
            window_toggle_maximize,
            window_close,
            window_hide,
            open_external_url,
            ensure_admin_launch,
            set_launch_on_startup,
            proxy_status,
            set_system_proxy,
            fetch_remote_text,
            fetch_remote_subscription,
            revoke_hwid_device,
            public_ip_snapshot,
            connectivity_probe,
            repair_runtime_environment,
            prepare_runtime_repair,
            server_ping,
            traffic_snapshot,
            traffic_session_start,
            read_runtime_log,
            list_running_apps,
            list_windows_services,
            native_app_info,
            pick_executable_path,
            restart_application
        ];
            handler(invoke)
        })
        .build(tauri::generate_context!())
        .expect("error while building VKarmani Desktop")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                if startup_commands_blocked(app) { startup_note_clean_exit(app); return; }
                if !app
                    .state::<AppState>()
                    .exit_approved
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    api.prevent_exit();
                    let _ = begin_state_handoff(app, HandoffAction::Quit);
                } else {
                    startup_note_clean_exit(app);
                }
            }
        });
}
