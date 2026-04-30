use super::*;

pub(crate) fn tune_outbound_for_performance(outbound: &mut Value) {
    let Some(outbound_map) = outbound.as_object_mut() else {
        return;
    };

    let protocol = outbound_map
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // Hysteria/Hysteria2 is QUIC/UDP based. TCP socket options do not help it and can make
    // generated configs invalid/noisier, so keep it untouched.
    if protocol.eq_ignore_ascii_case("hysteria") || protocol.eq_ignore_ascii_case("hysteria2") {
        return;
    }

    let stream_settings = outbound_map
        .entry("streamSettings".to_string())
        .or_insert_with(|| json!({}));

    let Some(stream_map) = stream_settings.as_object_mut() else {
        return;
    };

    let network = stream_map
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("raw")
        .to_string();

    let sockopt = stream_map
        .entry("sockopt".to_string())
        .or_insert_with(|| json!({}));

    if let Some(sockopt_map) = sockopt.as_object_mut() {
        // Keep-alive helps detect dead TCP sessions faster and avoids hanging
        // reconnects. TCP Fast Open is best-effort in Xray/Windows: unsupported
        // systems ignore it without blocking startup.
        sockopt_map
            .entry("tcpKeepAliveInterval".to_string())
            .or_insert_with(|| json!(30));
        sockopt_map
            .entry("tcpFastOpen".to_string())
            .or_insert_with(|| json!(true));
    }

    // XHTTP/HTTPUpgrade/WS/GRPC already multiplex at their transport layer or
    // are sensitive to mux. Do not force Xray mux globally: it can hurt speed
    // on modern Reality/XHTTP nodes.
    if matches!(network.as_str(), "xhttp" | "grpc" | "ws" | "httpupgrade") {
        outbound_map.remove("mux");
    }
}


const ROUTING_EXCLUSION_LIMIT: usize = 300;

fn is_valid_domain_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    let bytes = label.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn normalize_route_domain(raw_value: &str) -> Option<String> {
    let mut value = raw_value.trim().to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return None;
    }

    for prefix in ["https://", "http://", "socks5://", "socks4://"] {
        if value.starts_with(prefix) {
            value = value.trim_start_matches(prefix).to_string();
            break;
        }
    }

    value = value
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_string();

    if let Some(stripped) = value.strip_prefix("*.") {
        value = format!(".{stripped}");
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|ch| ch.is_ascii_digit()) {
            value = host.to_string();
        }
    }

    let domain = value.strip_prefix('.').unwrap_or(&value);
    if domain.is_empty() || domain.contains("..") || domain.contains('_') {
        return None;
    }

    if !domain.split('.').all(is_valid_domain_label) {
        return None;
    }

    Some(value)
}

fn normalize_route_ip(raw_value: &str) -> Option<String> {
    let value = raw_value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some((ip, prefix)) = value.split_once('/') {
        let parsed_ip = ip.trim().parse::<Ipv4Addr>().ok()?;
        let parsed_prefix = prefix.trim().parse::<u8>().ok()?;
        if parsed_prefix > 32 {
            return None;
        }
        return Some(format!("{parsed_ip}/{parsed_prefix}"));
    }

    value.trim().parse::<Ipv4Addr>().ok().map(|ip| ip.to_string())
}

fn tld_domain_matcher(tld: &str) -> String {
    format!("regexp:(^|\\.){tld}$")
}

fn custom_domain_matcher(domain: &str) -> String {
    if let Some(suffix) = domain.strip_prefix('.') {
        return tld_domain_matcher(&suffix.replace('.', "\\."));
    }

    format!("domain:{domain}")
}

pub(crate) fn build_routing_exclusion_rule_plan(
    exclusions: Option<&RoutingExclusionSettingsPayload>,
) -> RoutingExclusionRulePlan {
    let mut plan = RoutingExclusionRulePlan {
        domain_rules: Vec::new(),
        ip_rules: Vec::new(),
        skipped_notes: Vec::new(),
    };

    let Some(exclusions) = exclusions else {
        return plan;
    };

    if !exclusions.enabled {
        return plan;
    }

    if exclusions.bypass_ru_domains {
        plan.domain_rules.push(tld_domain_matcher("ru"));
    }
    if exclusions.bypass_su_domains {
        plan.domain_rules.push(tld_domain_matcher("su"));
    }
    if exclusions.bypass_rf_domains {
        plan.domain_rules.push(tld_domain_matcher("xn--p1ai"));
    }

    for raw_domain in &exclusions.domains {
        if plan.domain_rules.len() >= ROUTING_EXCLUSION_LIMIT {
            plan.skipped_notes.push("Routing exclusions: часть доменов пропущена из-за лимита direct-правил.".to_string());
            break;
        }

        match normalize_route_domain(raw_domain) {
            Some(domain) => {
                let matcher = custom_domain_matcher(&domain);
                if !plan.domain_rules.iter().any(|item| item == &matcher) {
                    plan.domain_rules.push(matcher);
                }
            }
            None => plan
                .skipped_notes
                .push(format!("Routing exclusions: домен пропущен как некорректный: {raw_domain}")),
        }
    }

    for raw_ip in &exclusions.ips {
        if plan.ip_rules.len() >= ROUTING_EXCLUSION_LIMIT {
            plan.skipped_notes.push("Routing exclusions: часть IPv4/CIDR пропущена из-за лимита direct-правил.".to_string());
            break;
        }

        match normalize_route_ip(raw_ip) {
            Some(ip) => {
                if !plan.ip_rules.iter().any(|item| item == &ip) {
                    plan.ip_rules.push(ip);
                }
            }
            None => plan
                .skipped_notes
                .push(format!("Routing exclusions: IPv4/CIDR пропущен как некорректный: {raw_ip}")),
        }
    }

    plan
}

fn routing_exclusion_inbound_tags(network_mode: &str) -> Vec<&'static str> {
    if network_mode == "tun" {
        vec!["tun-in"]
    } else {
        vec!["socks-in", "http-in"]
    }
}

pub(crate) fn build_xray_config(
    template: &RuntimeTemplate,
    network_mode: &str,
    ip_stack: &str,
    send_through_ip: Option<&str>,
    split_tunnel_entries: &[SplitTunnelEntryPayload],
    routing_exclusions: Option<&RoutingExclusionSettingsPayload>,
    runtime_log_path: Option<&Path>,
) -> (Value, SplitTunnelRulePlan, RoutingExclusionRulePlan) {
    let plan = if network_mode == "tun" {
        build_split_tunnel_rule_plan(split_tunnel_entries)
    } else {
        SplitTunnelRulePlan {
            process_matches: Vec::new(),
            resolved_apps: 0,
            resolved_services: 0,
            skipped_notes: Vec::new(),
        }
    };

    let routing_exclusion_plan = build_routing_exclusion_rule_plan(routing_exclusions);

    let mut outbound = if template.outbound.is_object() {
        template.outbound.clone()
    } else {
        json!({})
    };

    tune_outbound_for_performance(&mut outbound);

    if let Some(map) = outbound.as_object_mut() {
        map.insert("tag".to_string(), Value::String("proxy".to_string()));
        if let Some(ip) = send_through_ip {
            // В TUN режиме исходный адрес должен соответствовать текущему физическому
            // адаптеру после остановки старого runtime. Не сохраняем sendThrough из
            // импортированного/старого шаблона, иначе можно получить loop при soft switch.
            map.insert("sendThrough".to_string(), Value::String(ip.to_string()));
        }
    }

    let mut inbounds = vec![
        json!({
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {
                "udp": true,
                "auth": "noauth"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true
            }
        }),
        json!({
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": HTTP_PORT,
            "protocol": "http",
            "settings": {},
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"],
                "routeOnly": true
            }
        }),
        json!({
            "tag": "api-in",
            "listen": "127.0.0.1",
            "port": XRAY_API_PORT,
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1"
            }
        }),
    ];

    let mut routing_rules = vec![json!({
        "inboundTag": ["api-in"],
        "outboundTag": "api",
        "type": "field",
        "ruleTag": "xray-api"
    })];

    let routing_exclusion_inbounds = routing_exclusion_inbound_tags(network_mode);
    if !routing_exclusion_plan.domain_rules.is_empty() {
        routing_rules.push(json!({
            "inboundTag": routing_exclusion_inbounds.clone(),
            "domain": routing_exclusion_plan.domain_rules.clone(),
            "outboundTag": "direct",
            "ruleTag": "user-domain-direct"
        }));
    }
    if !routing_exclusion_plan.ip_rules.is_empty() {
        routing_rules.push(json!({
            "inboundTag": routing_exclusion_inbounds,
            "ip": routing_exclusion_plan.ip_rules.clone(),
            "outboundTag": "direct",
            "ruleTag": "user-ip-direct"
        }));
    }

    if network_mode == "tun" {
        inbounds.push(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": TUN_INTERFACE_NAME,
                "MTU": 1400,
                "userLevel": 0
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true
            }
        }));

        routing_rules.push(json!({
            "inboundTag": ["tun-in"],
            "process": ["self/", "xray/"],
            "outboundTag": "direct",
            "ruleTag": "tun-core-self-direct"
        }));

        routing_rules.push(json!({
            "inboundTag": ["tun-in"],
            "ip": private_bypass_cidrs(),
            "outboundTag": "direct",
            "ruleTag": "tun-private-direct"
        }));

        routing_rules.push(json!({
            "inboundTag": ["tun-in"],
            "domain": ["domain:localhost", "full:localhost", "keyword:.local"],
            "outboundTag": "direct",
            "ruleTag": "tun-local-domain-direct"
        }));


        routing_rules.push(json!({
            "inboundTag": ["tun-in"],
            "ip": ["::/0"],
            "outboundTag": "block",
            "ruleTag": "tun-ipv6-leak-guard"
        }));

        if !plan.process_matches.is_empty() {
            routing_rules.push(json!({
                "inboundTag": ["tun-in"],
                "process": plan.process_matches.clone(),
                "outboundTag": "proxy",
                "ruleTag": "tun-selected-processes"
            }));
            routing_rules.push(json!({
                "inboundTag": ["tun-in"],
                "outboundTag": "direct",
                "ruleTag": "tun-bypass-unselected"
            }));
        } else {
            routing_rules.push(json!({
                "inboundTag": ["tun-in"],
                "outboundTag": "direct",
                "ruleTag": "tun-empty-selection-direct"
            }));
        }
    }

    let domain_strategy = if network_mode == "tun" {
        "IPOnDemand"
    } else {
        "AsIs"
    };

    let direct_outbound = if let Some(ip) = send_through_ip {
        json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": {},
            "sendThrough": ip
        })
    } else {
        json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        })
    };

    let log_object = if let Some(path) = runtime_log_path {
        json!({
            "loglevel": "warning",
            "error": path.to_string_lossy().to_string(),
            "access": ""
        })
    } else {
        json!({
            "loglevel": "warning"
        })
    };

    let dns_query_strategy = if ip_stack == "ipv6" {
        "UseIPv6"
    } else {
        "UseIPv4"
    };

    (
        json!({
            "log": log_object,
            "dns": {
                "queryStrategy": dns_query_strategy,
                "servers": ["1.1.1.1", "8.8.8.8", "localhost"]
            },
            "api": {
                "tag": "api",
                "services": ["StatsService"]
            },
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": true,
                        "statsUserDownlink": true
                    }
                },
                "system": {
                    "statsInboundUplink": true,
                    "statsInboundDownlink": true,
                    "statsOutboundUplink": true,
                    "statsOutboundDownlink": true
                }
            },
            "stats": {},
            "inbounds": inbounds,
            "routing": {
                "domainStrategy": domain_strategy,
                "rules": routing_rules
            },
            "outbounds": [
                outbound,
                direct_outbound,
                {
                    "tag": "block",
                    "protocol": "blackhole",
                    "settings": {}
                }
            ]
        }),
        plan,
        routing_exclusion_plan,
    )
}

pub(crate) fn value_as_valid_port(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .map(|port| port as u16)
}

pub(crate) fn extract_outbound_address_and_port(template: &RuntimeTemplate) -> (Option<String>, u16) {
    let default_port = 443_u16;
    let settings = template.outbound.get("settings");

    if let Some(vnext) = settings
        .and_then(|value| value.get("vnext"))
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
    {
        let address = vnext
            .get("address")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        let port = vnext
            .get("port")
            .and_then(value_as_valid_port)
            .unwrap_or(default_port);
        return (address, port);
    }

    if let Some(server) = settings
        .and_then(|value| value.get("servers"))
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
    {
        let address = server
            .get("address")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        let port = server
            .get("port")
            .and_then(value_as_valid_port)
            .unwrap_or(default_port);
        return (address, port);
    }

    (None, default_port)
}

pub(crate) fn resolve_ipv4_address(host: &str, port: u16) -> Option<String> {
    resolve_socket_addresses(host, port)
        .ok()
        .and_then(|items| items.into_iter().find(|addr| addr.ip().is_ipv4()))
        .map(|addr| addr.ip().to_string())
}

pub(crate) fn detect_primary_ipv4_address() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    let addr = socket.local_addr().ok()?;
    if addr.ip().is_ipv4() {
        Some(addr.ip().to_string())
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_net_command(program: &str, args: &[String], timeout: Duration, context: &str) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args);
    run_command_with_timeout(command, timeout, context)
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_net_command_str(program: &str, args: &[&str], timeout: Duration, context: &str) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args);
    run_command_with_timeout(command, timeout, context)
}

#[cfg(target_os = "windows")]
pub(crate) fn default_route_snapshot() -> Result<DefaultRouteSnapshot, String> {
    // Fast path: `route.exe` starts much faster than PowerShell/Get-NetRoute.
    // Expected active-route columns: destination, mask, gateway, interface, metric.
    let raw = run_windows_net_command_str(
        "route",
        &["print", "-4", "0.0.0.0"],
        Duration::from_secs(3),
        "route print default route",
    )?;

    let mut best: Option<(String, u32)> = None;
    for line in raw.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 5 || parts[0] != "0.0.0.0" || parts[1] != "0.0.0.0" {
            continue;
        }

        let gateway = parts[2].trim();
        if gateway.eq_ignore_ascii_case("on-link") || gateway == "0.0.0.0" {
            continue;
        }

        let metric = parts
            .last()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(u32::MAX);

        match &best {
            Some((_, current_metric)) if *current_metric <= metric => {}
            _ => best = Some((gateway.to_string(), metric)),
        }
    }

    best
        .map(|(next_hop, _)| DefaultRouteSnapshot {
            interface_index: 0,
            next_hop,
        })
        .ok_or_else(|| "Default route not found".to_string())
}

#[cfg(target_os = "windows")]
pub(crate) fn find_tun_interface_index(interface_name: &str) -> Result<u32, String> {
    let raw = run_windows_net_command_str(
        "netsh",
        &["interface", "ipv4", "show", "interfaces"],
        Duration::from_secs(3),
        "netsh interface list",
    )?;

    let wanted = interface_name.trim().to_ascii_lowercase();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.to_ascii_lowercase().ends_with(&wanted) {
            continue;
        }

        if let Some(index) = trimmed
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u32>().ok())
        {
            return Ok(index);
        }
    }

    Err(format!("TUN интерфейс {interface_name} пока не найден."))
}

#[cfg(target_os = "windows")]
pub(crate) fn wait_for_tun_interface(interface_name: &str) -> Result<u32, String> {
    // Xray usually creates Wintun quickly. Poll with a lightweight netsh call instead
    // of repeatedly starting PowerShell/Get-NetAdapter.
    let mut last_error = String::new();
    for _ in 0..24 {
        match find_tun_interface_index(interface_name) {
            Ok(index) => return Ok(index),
            Err(error) => last_error = error,
        }

        std::thread::sleep(Duration::from_millis(150));
    }

    Err(if last_error.is_empty() {
        format!("TUN интерфейс {interface_name} не появился после запуска Xray.")
    } else {
        format!("{last_error} После запуска Xray интерфейс не появился вовремя.")
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn route_delete(destination: &str, mask: &str, gateway: Option<&str>, if_index: Option<u32>) {
    let mut args = vec![
        "delete".to_string(),
        destination.to_string(),
        "mask".to_string(),
        mask.to_string(),
    ];

    if let Some(gateway) = gateway.filter(|value| !value.trim().is_empty()) {
        args.push(gateway.to_string());
    }

    if let Some(index) = if_index.filter(|value| *value > 0) {
        args.push("if".to_string());
        args.push(index.to_string());
    }

    let _ = run_windows_net_command("route", &args, Duration::from_secs(2), "route delete");
}

#[cfg(target_os = "windows")]
pub(crate) fn route_add(destination: &str, mask: &str, gateway: &str, metric: u32, if_index: Option<u32>) -> Result<(), String> {
    let mut args = vec![
        "add".to_string(),
        destination.to_string(),
        "mask".to_string(),
        mask.to_string(),
        gateway.to_string(),
        "metric".to_string(),
        metric.to_string(),
    ];

    if let Some(index) = if_index.filter(|value| *value > 0) {
        args.push("if".to_string());
        args.push(index.to_string());
    }

    run_windows_net_command("route", &args, Duration::from_secs(3), "route add").map(|_| ())
}

#[cfg(target_os = "windows")]
pub(crate) fn configure_tun_routes_fast(interface_name: &str, server_ip: Option<&str>) -> Result<(), String> {
    // Snapshot the real default route before adding split-default TUN routes.
    // Taking it afterwards can capture the just-created TUN route on some Windows setups
    // and break the /32 escape route to the VPN server.
    let default_route_before_tun = default_route_snapshot().ok();
    let tun_index = wait_for_tun_interface(interface_name)?;

    // Critical for soft server switching: protect the VPN server endpoint before
    // split-default routes are added. Otherwise Windows can briefly route the new
    // Xray outbound into the just-created TUN interface, which causes reconnect loops
    // and high xray.exe CPU on some machines.
    if let Some(ip) = server_ip.filter(|value| !value.trim().is_empty()) {
        let default_route = default_route_before_tun.as_ref().ok_or_else(|| {
            "Не удалось снять default route до добавления TUN routes; fallback PowerShell будет использован для безопасной настройки server /32 route.".to_string()
        })?;

        if default_route.next_hop.trim().is_empty() || default_route.next_hop == "0.0.0.0" {
            return Err("Default route не содержит gateway для server /32 route; fallback PowerShell будет использован.".to_string());
        }

        route_delete(ip, "255.255.255.255", None, None);
        if let Err(error) = route_add(ip, "255.255.255.255", &default_route.next_hop, 1, None) {
            return Err(format!("Не удалось добавить /32 route до VPN-сервера через исходный gateway: {error}"));
        }
    }

    route_delete("0.0.0.0", "128.0.0.0", Some("0.0.0.0"), Some(tun_index));
    route_delete("128.0.0.0", "128.0.0.0", Some("0.0.0.0"), Some(tun_index));

    // Split-default routing keeps the original default route alive, but sends public
    // IPv4 traffic through Wintun. `0.0.0.0` is the on-link gateway for the TUN interface.
    if let Err(error) = route_add("0.0.0.0", "128.0.0.0", "0.0.0.0", 6, Some(tun_index)) {
        let _ = cleanup_tun_routes(interface_name, server_ip);
        return Err(error);
    }

    if let Err(error) = route_add("128.0.0.0", "128.0.0.0", "0.0.0.0", 6, Some(tun_index)) {
        let _ = cleanup_tun_routes(interface_name, server_ip);
        return Err(error);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn configure_tun_routes_powershell(interface_name: &str, server_ip: Option<&str>) -> Result<(), String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.State -eq 'Alive' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 InterfaceAlias, InterfaceIndex, NextHop
if (-not $route) { throw 'Default route not found' }
$route | ConvertTo-Json -Compress
"#;

    let raw = run_powershell(script)?;
    let default_route = serde_json::from_str::<DefaultRouteSnapshot>(&raw)
        .map_err(|error| format!("Не удалось разобрать снимок default route: {error}"))?;

    let wait_script = format!(
        r#"
$adapter = Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue
if ($adapter) {{ 'ready' }}
"#,
        ps_quote(interface_name)
    );

    for _ in 0..20 {
        if run_powershell(&wait_script)
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("ready")
        {
            break;
        }

        std::thread::sleep(Duration::from_millis(250));
    }

    let server_route = if let Some(ip) = server_ip.filter(|value| !value.trim().is_empty()) {
        if default_route.next_hop.trim().is_empty() || default_route.next_hop == "0.0.0.0" {
            String::new()
        } else {
            format!(
                "Remove-NetRoute -DestinationPrefix '{ip}/32' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null\nNew-NetRoute -DestinationPrefix '{ip}/32' -InterfaceIndex {} -NextHop '{}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null",
                default_route.interface_index,
                ps_quote(&default_route.next_hop),
                ip = ps_quote(ip)
            )
        }
    } else {
        String::new()
    };

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$tun = '{}'
Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias $tun -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias $tun -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
{}
New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias $tun -NextHop '0.0.0.0' -RouteMetric 6 -PolicyStore ActiveStore | Out-Null
New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias $tun -NextHop '0.0.0.0' -RouteMetric 6 -PolicyStore ActiveStore | Out-Null
"#,
        ps_quote(interface_name),
        server_route
    );

    run_powershell(&script)?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn configure_tun_routes(interface_name: &str, server_ip: Option<&str>) -> Result<(), String> {
    match configure_tun_routes_fast(interface_name, server_ip) {
        Ok(()) => Ok(()),
        Err(fast_error) => {
            let fallback = configure_tun_routes_powershell(interface_name, server_ip);
            if fallback.is_ok() {
                Ok(())
            } else {
                fallback.map_err(|fallback_error| {
                    format!(
                        "Быстрая настройка TUN через route.exe/netsh не удалась: {fast_error}. Fallback PowerShell тоже не сработал: {fallback_error}"
                    )
                })
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn configure_tun_routes(_interface_name: &str, _server_ip: Option<&str>) -> Result<(), String> {
    Err("TUN маршруты сейчас реализованы только для Windows сборки VKarmani.".into())
}

#[cfg(target_os = "windows")]
pub(crate) fn apply_tun_ipv6_route_guard(interface_name: &str) -> Result<(), String> {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$tun = '{}'
$adapter = Get-NetAdapter -Name $tun -ErrorAction SilentlyContinue
if (-not $adapter) {{ throw "TUN adapter not found for IPv6 leak guard" }}
Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/1' -InterfaceAlias $tun -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '8000::/1' -InterfaceAlias $tun -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
try {{
  New-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/1' -InterfaceAlias $tun -NextHop '::' -RouteMetric 6 -PolicyStore ActiveStore | Out-Null
  New-NetRoute -AddressFamily IPv6 -DestinationPrefix '8000::/1' -InterfaceAlias $tun -NextHop '::' -RouteMetric 6 -PolicyStore ActiveStore | Out-Null
}} catch {{
  throw "IPv6 split-default route could not be applied: $($_.Exception.Message)"
}}
"#,
        ps_quote(interface_name)
    );

    run_powershell(&script).map(|_| ())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn apply_tun_ipv6_route_guard(_interface_name: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_tun_ipv6_routes(interface_name: &str) {
    let script = format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$tun = '{}'
Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/1' -InterfaceAlias $tun -Confirm:$false | Out-Null
Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '8000::/1' -InterfaceAlias $tun -Confirm:$false | Out-Null
"#,
        ps_quote(interface_name)
    );
    let _ = run_powershell(&script);
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn cleanup_tun_ipv6_routes(_interface_name: &str) {}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_tun_routes(interface_name: &str, server_ip: Option<&str>) -> Result<(), String> {
    cleanup_tun_ipv6_routes(interface_name);

    if let Ok(tun_index) = find_tun_interface_index(interface_name) {
        route_delete("0.0.0.0", "128.0.0.0", Some("0.0.0.0"), Some(tun_index));
        route_delete("128.0.0.0", "128.0.0.0", Some("0.0.0.0"), Some(tun_index));
    }

    if let Some(ip) = server_ip.filter(|value| !value.trim().is_empty()) {
        route_delete(ip, "255.255.255.255", None, None);
    }

    // Best-effort fallback for older Windows builds / localized route output.
    let server_cleanup = if let Some(ip) = server_ip.filter(|value| !value.trim().is_empty()) {
        format!(
            "Remove-NetRoute -DestinationPrefix '{}/32' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null",
            ps_quote(ip)
        )
    } else {
        String::new()
    };

    let script = format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$tun = '{}'
Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias $tun -Confirm:$false | Out-Null
Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias $tun -Confirm:$false | Out-Null
{}
"#,
        ps_quote(interface_name),
        server_cleanup
    );

    let _ = run_powershell(&script);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn cleanup_tun_routes(_interface_name: &str, _server_ip: Option<&str>) -> Result<(), String> {
    Ok(())
}
