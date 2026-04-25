const TRAY_ID: &str = "vkarmani-main-tray";

fn build_tray_menu(app: &AppHandle, connected: bool, proxy_active: bool, authorized: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let show_item = MenuItem::with_id(app, "show", "Открыть VKarmani", true, None::<&str>)?;
    let connect_item = MenuItem::with_id(app, "connect", "Быстрое подключение", true, None::<&str>)?;
    let disconnect_item = MenuItem::with_id(app, "disconnect", "Отключиться", true, None::<&str>)?;
    let restart_app_item = MenuItem::with_id(app, "restart_app", "Перезапустить программу", true, None::<&str>)?;
    let restart_proxy_item = MenuItem::with_id(app, "restart_proxy", "Перезапустить прокси", true, None::<&str>)?;
    let logout_item = MenuItem::with_id(app, "logout", "Выйти из ЛК", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;

    let mut items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![&show_item];

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

fn tray_runtime_flags(app: &AppHandle) -> (bool, bool, bool) {
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

    (connected, proxy_active, authorized)
}

fn refresh_tray_menu(app: &AppHandle) {
    let (connected, proxy_active, authorized) = tray_runtime_flags(app);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        match build_tray_menu(app, connected, proxy_active, authorized) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(error) => {
                let _ = append_interface_event(app, &format!("Не удалось обновить меню трея: {error}"));
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = append_interface_event(app, "Повторный запуск: активируем уже открытое окно VKarmani.");
            reveal_main_window(app);
            let _ = app.emit("vkarmani://tray-action", "show");
        }))
        .manage(AppState::default())
        .setup(|app| {
            let _ = interface_logs_dir(&app.handle());
            let _ = routing_logs_dir(&app.handle());
            let _ = ensure_log_tree(&app.handle());
            let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, None);
            let _ = cleanup_runtime_config_files(&app.handle());
            let _ = append_interface_event(&app.handle(), "Приложение запущено. Структура логов проверена.");
            let _ = append_runtime_event(&app.handle(), "Routing/runtime лог инициализирован. Ожидание действий пользователя.");
            let menu = build_tray_menu(&app.handle(), false, false, false)?;

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
                    "restart_app" => {
                        let _ = append_interface_event(app, "Tray: перезапуск приложения.");
                        let _ = restart_application(app.clone());
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
                        cleanup_application(app, "tray_quit");
                        app.exit(0)
                    },
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        reveal_main_window(&tray.app_handle());
                    }
                })
                .build(app)?;

            app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bootstrap_info,
            save_access_key_secure,
            load_access_key_secure,
            clear_access_key_secure,
            runtime_status,
            set_session_authorized,
            request_connect,
            request_disconnect,
            cache_profile_sync,
            write_interface_log,
            write_routing_log,
            request_show,
            window_minimize,
            window_toggle_maximize,
            window_close,
            window_hide,
            window_start_drag,
            ensure_admin_launch,
            set_launch_on_startup,
            proxy_status,
            set_system_proxy,
            fetch_remote_text,
            revoke_hwid_device,
            public_ip_snapshot,
            connectivity_probe,
            read_runtime_log,
            list_running_apps,
            restart_application
        ])
        .build(tauri::generate_context!())
        .expect("error while building VKarmani Desktop")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                cleanup_application(app, "exit_requested");
            }
        });
}
