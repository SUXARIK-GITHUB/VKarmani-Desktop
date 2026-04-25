fn build_runtime_status(app: &AppHandle, state: tauri::State<AppState>) -> RuntimeStatus {
    sync_runtime_liveness(app, &state);
    let connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    let active_server_label = state
        .active_server_label
        .lock()
        .ok()
        .and_then(|value| value.clone());
    let profile_count = state.profile_count.lock().map(|value| *value).unwrap_or_default();
    let last_sync_source = state
        .last_sync_source
        .lock()
        .ok()
        .and_then(|value| value.clone());
    let last_exit_code = state.last_exit_code.lock().ok().and_then(|value| *value);
    let core_path = resolve_core_path(app).map(|path| path.to_string_lossy().to_string());
    let proxy_snapshot = current_proxy_snapshot().ok();

    let runtime_snapshot = state.runtime.lock().ok().and_then(|value| {
        value.as_ref().map(|runtime| {
            (
                runtime.core_path.clone(),
                runtime.config_path.clone(),
                runtime.log_path.clone(),
                runtime.server_id.clone(),
                runtime.started_at.clone(),
                runtime.network_mode.clone(),
                runtime.tun_interface_name.clone(),
            )
        })
    });

    let current_network_mode = runtime_snapshot.as_ref().map(|snapshot| snapshot.5.clone());
    let current_tun_name = runtime_snapshot.as_ref().and_then(|snapshot| snapshot.6.clone());

    let message = if connected && current_network_mode.as_deref() == Some("tun") {
        format!(
            "Xray TUN режим активен{}. VKarmani направляет выбранные процессы через VPN, остальной трафик выходит напрямую.",
            current_tun_name
                .as_deref()
                .map(|name| format!(" через интерфейс {name}"))
                .unwrap_or_default()
        )
    } else if connected {
        "Xray sidecar запущен. Можно переводить системный HTTP/HTTPS трафик в локальный proxy-режим.".to_string()
    } else if core_path.is_some() {
        "Xray-core найден. Можно собирать runtime-профиль, запускать sidecar и тестировать маршрут.".to_string()
    } else {
        core_not_found_message(app)
    };

    RuntimeStatus {
        bridge: "tauri".into(),
        core_installed: core_path.is_some(),
        tunnel_active: connected,
        active_server_label,
        profile_count: Some(profile_count),
        last_sync_source,
        message,
        core_path: runtime_snapshot.as_ref().map(|snapshot| snapshot.0.clone()).or(core_path),
        config_path: None,
        log_path: runtime_snapshot.as_ref().map(|snapshot| snapshot.2.clone()),
        launch_mode: if runtime_snapshot.is_some() {
            "xray-sidecar".into()
        } else {
            "mock".into()
        },
        socks_port: Some(SOCKS_PORT),
        http_port: Some(HTTP_PORT),
        last_prepared_server_id: runtime_snapshot.as_ref().map(|snapshot| snapshot.3.clone()),
        last_prepared_at: runtime_snapshot.as_ref().map(|snapshot| snapshot.4.clone()),
        last_exit_code,
        system_proxy_enabled: proxy_snapshot.as_ref().map(|snapshot| snapshot.enabled),
        proxy_server: proxy_snapshot.as_ref().and_then(|snapshot| snapshot.server.clone()),
        proxy_bypass: proxy_snapshot.as_ref().and_then(|snapshot| snapshot.bypass.clone()),
        network_mode: current_network_mode,
        tun_interface_name: current_tun_name,
    }
}



fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let [a, b, c, d] = octets;

    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a >= 240)
        || (a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped);
    }

    let octets = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (octets[0] & 0xfe) == 0xfc // fc00::/7 unique local
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80) // fe80::/10 link-local
        || (octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8) // 2001:db8::/32 docs
}

fn is_forbidden_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_forbidden_ipv4(value),
        IpAddr::V6(value) => is_forbidden_ipv6(value),
    }
}

fn is_forbidden_remote_host_label(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".home.arpa")
}
