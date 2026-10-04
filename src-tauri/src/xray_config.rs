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
        // reconnects. Do not force TCP Fast Open: on some Windows/network-driver
        // combinations it can make reconnects less predictable.
        sockopt_map
            .entry("tcpKeepAliveInterval".to_string())
            .or_insert_with(|| json!(30));
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

    value
        .trim()
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| ip.to_string())
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
            plan.skipped_notes.push(
                "Routing exclusions: часть доменов пропущена из-за лимита direct-правил."
                    .to_string(),
            );
            break;
        }

        match normalize_route_domain(raw_domain) {
            Some(domain) => {
                let matcher = custom_domain_matcher(&domain);
                if !plan.domain_rules.iter().any(|item| item == &matcher) {
                    plan.domain_rules.push(matcher);
                }
            }
            None => plan.skipped_notes.push(format!(
                "Routing exclusions: домен пропущен как некорректный: {raw_domain}"
            )),
        }
    }

    for raw_ip in &exclusions.ips {
        if plan.ip_rules.len() >= ROUTING_EXCLUSION_LIMIT {
            plan.skipped_notes.push(
                "Routing exclusions: часть IPv4/CIDR пропущена из-за лимита direct-правил."
                    .to_string(),
            );
            break;
        }

        match normalize_route_ip(raw_ip) {
            Some(ip) => {
                if !plan.ip_rules.iter().any(|item| item == &ip) {
                    plan.ip_rules.push(ip);
                }
            }
            None => plan.skipped_notes.push(format!(
                "Routing exclusions: IPv4/CIDR пропущен как некорректный: {raw_ip}"
            )),
        }
    }

    plan
}

fn routing_exclusion_inbound_tags(network_mode: &str) -> Vec<&'static str> {
    let mut tags = vec!["socks-in", "http-in"];
    if network_mode == "tun" {
        tags.push("tun-in");
    }
    tags
}

fn value_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
}

fn outbound_tag(value: &Value) -> Option<String> {
    value_string_field(value, "tag")
}

fn is_supported_proxy_protocol(protocol: &str) -> bool {
    matches!(
        protocol.to_ascii_lowercase().as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "hysteria2"
    )
}

fn apply_send_through_to_proxy_outbounds(outbounds: &mut [Value], send_through_ip: Option<&str>) {
    let Some(ip) = send_through_ip else {
        return;
    };

    for outbound in outbounds {
        let protocol = outbound
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_supported_proxy_protocol(protocol) {
            continue;
        }

        if let Some(map) = outbound.as_object_mut() {
            set_client_owned_xray_field(map, "sendThrough", Value::String(ip.to_string()));
        }
    }
}

// Provider tags must never collide with client adapters or accidentally select
// an injected loopback/direct outbound in a provider balancer.
fn adapter_namespace(config: &Value) -> String {
    let mut prefixes = Vec::new();
    for section in ["outbounds", "inbounds"] {
        if let Some(items) = config.get(section).and_then(Value::as_array) {
            prefixes.extend(
                items
                    .iter()
                    .filter_map(|item| item.get("tag").and_then(Value::as_str))
                    .filter(|tag| !tag.is_empty()),
            );
        }
    }
    if let Some(items) = config
        .pointer("/routing/balancers")
        .and_then(Value::as_array)
    {
        for item in items {
            if let Some(selectors) = item.get("selector").and_then(Value::as_array) {
                prefixes.extend(
                    selectors
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|tag| !tag.is_empty()),
                );
            }
        }
    }
    for index in 0..=prefixes.len() {
        let prefix = if index == 0 {
            "__vkarmani.".into()
        } else {
            format!(
                "{}vkarmani.",
                char::from_u32(0xe000 + index as u32).unwrap_or('\u{f8ff}')
            )
        };
        if !prefixes
            .iter()
            .any(|tag| prefix.starts_with(tag) || tag.starts_with(&prefix))
        {
            return prefix;
        }
    }
    unreachable!("finite tag set cannot cover all allocated namespace prefixes")
}

fn merge_stats_policy(config: &mut Value) {
    if !config["policy"].is_object() {
        config["policy"] = json!({});
    }
    if !config["policy"]["levels"].is_object() {
        config["policy"]["levels"] = json!({});
    }
    if !config["policy"]["levels"]["0"].is_object() {
        config["policy"]["levels"]["0"] = json!({});
    }
    if !config["policy"]["system"].is_object() {
        config["policy"]["system"] = json!({});
    }
    for (path, flags) in [
        (
            "/policy/levels/0",
            &["statsUserUplink", "statsUserDownlink"][..],
        ),
        (
            "/policy/system",
            &[
                "statsInboundUplink",
                "statsInboundDownlink",
                "statsOutboundUplink",
                "statsOutboundDownlink",
            ][..],
        ),
    ] {
        let map = config
            .pointer_mut(path)
            .and_then(Value::as_object_mut)
            .expect("policy object created");
        for flag in flags {
            map.entry((*flag).to_string()).or_insert(json!(true));
        }
    }
    if config.get("stats").map_or(true, Value::is_null) {
        config["stats"] = json!({});
    }
}

// Go encoding/json matches ASCII field names case-insensitively, including
// Unicode simple-fold equivalents long-s and Kelvin sign. Rust JSON map lookup
// is exact. Remove every equivalent spelling at client-owned boundaries before
// serialization so a later alias cannot override the sanitized canonical key.
fn xray_json_field_matches(name: &str, field: &str) -> bool {
    name.chars()
        .map(|character| match character {
            '\u{017f}' => 's',
            '\u{212a}' => 'k',
            other => other.to_ascii_lowercase(),
        })
        .eq(field
            .chars()
            .map(|character| character.to_ascii_lowercase()))
}

fn set_client_owned_xray_field(map: &mut serde_json::Map<String, Value>, key: &str, value: Value) {
    map.retain(|name, _| !xray_json_field_matches(name, key));
    map.insert(key.into(), value);
}

struct FullConfigAdapterSettings<'a> {
    log_object: Value,
    domain_strategy: &'a str,
    dns_query_strategy: &'a str,
    send_through_ip: Option<&'a str>,
}

fn build_from_full_xray_config_template(
    template: &RuntimeTemplate,
    full_config: &Value,
    mut inbounds: Vec<Value>,
    mut adapter_rules: Vec<Value>,
    mut direct_outbound: Value,
    mut block_outbound: Value,
    settings: FullConfigAdapterSettings<'_>,
) -> Option<Value> {
    let FullConfigAdapterSettings {
        log_object,
        domain_strategy,
        dns_query_strategy,
        send_through_ip,
    } = settings;
    let mut config = full_config.clone();
    config.as_object()?;
    // Optional Xray sections may be JSON null; materialize only sections that
    // the client adapter must augment, keeping the canonical input untouched.
    for section in ["log", "api"] {
        if config.get(section).is_some_and(Value::is_null) {
            config[section] = json!({});
        }
    }
    let namespace = adapter_namespace(&config);
    let own = |tag: &str| format!("{namespace}{tag}");
    let api_tag = config
        .pointer("/api/tag")
        .and_then(Value::as_str)
        .filter(|tag| !tag.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| own("api"));
    let mut outbounds = config.get("outbounds")?.as_array()?.clone();
    // Imported transport/mux/policy settings are not performance-tuned away.
    // TUN alone binds sockets to the observed physical address to prevent loops.
    apply_send_through_to_proxy_outbounds(&mut outbounds, send_through_ip);
    if let Some(ip) = send_through_ip {
        for outbound in &mut outbounds {
            if outbound.get("protocol").and_then(Value::as_str) == Some("freedom") {
                set_client_owned_xray_field(outbound.as_object_mut()?, "sendThrough", json!(ip));
            }
        }
    }
    let default_tag = if template.profile_kind.as_deref() == Some("node") {
        template.primary_outbound_tag.clone()
    } else {
        outbounds.first().and_then(outbound_tag)
    }
    .unwrap_or_else(|| own("default"));
    if outbounds
        .first()
        .is_some_and(|item| outbound_tag(item).is_none())
    {
        outbounds[0]["tag"] = json!(default_tag);
    }
    direct_outbound["tag"] = json!(own("direct"));
    block_outbound["tag"] = json!(own("block"));
    let provider_tags: Vec<String> = outbounds.iter().filter_map(outbound_tag).collect();
    // An empty selector means every ORIGINAL outbound, not the new adapters.
    if let Some(balancers) = config
        .pointer_mut("/routing/balancers")
        .and_then(Value::as_array_mut)
    {
        for balancer in balancers {
            if balancer
                .get("selector")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some("")))
            {
                balancer["selector"] = json!(provider_tags);
            }
        }
    }
    for inbound in &mut inbounds {
        if let Some(tag) = inbound
            .get("tag")
            .and_then(Value::as_str)
            .map(ToString::to_string)
        {
            inbound["tag"] = json!(own(&tag));
        }
    }
    for rule in &mut adapter_rules {
        if let Some(tags) = rule.get_mut("inboundTag").and_then(Value::as_array_mut) {
            for tag in tags {
                if let Some(original) = tag.as_str() {
                    *tag = json!(own(original));
                }
            }
        }
        if let Some(tag) = rule
            .get("outboundTag")
            .and_then(Value::as_str)
            .map(ToString::to_string)
        {
            rule["outboundTag"] = json!(if tag == "api" {
                api_tag.clone()
            } else if tag == "proxy" {
                own("dispatch-tun")
            } else {
                own(&tag)
            });
        }
    }
    let virtual_tags = [
        own("profile-socks"),
        own("profile-http"),
        own("profile-tun"),
    ];
    for (source, target) in [
        ("socks-in", "socks"),
        ("http-in", "http"),
        ("tun-in", "tun"),
    ] {
        outbounds.push(json!({"tag":own(&format!("dispatch-{target}")),"protocol":"loopback","settings":{"inboundTag":own(&format!("profile-{target}"))}}));
        if source != "tun-in" {
            adapter_rules.push(json!({"type":"field","inboundTag":[own(source)],"outboundTag":own(&format!("dispatch-{target}")),"ruleTag":own(&format!("enter-{target}"))}));
        }
    }
    let provider_rules = config
        .pointer("/routing/rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for mut rule in provider_rules {
        let scope = if let Some(tags) = rule.get("inboundTag").and_then(Value::as_array) {
            let mut mapped = Vec::new();
            for tag in tags {
                let declaration = full_config
                    .get("inbounds")
                    .and_then(Value::as_array)
                    .and_then(|items| items.iter().find(|item| item.get("tag") == Some(tag)));
                match declaration
                    .and_then(|item| item.get("protocol"))
                    .and_then(Value::as_str)
                {
                    Some("socks") => {
                        mapped.extend([json!(own("profile-socks")), json!(own("profile-tun"))])
                    }
                    Some("http") => {
                        mapped.extend([json!(own("profile-http")), json!(own("profile-tun"))])
                    }
                    _ => mapped.push(tag.clone()), // Preserve unknown selectors; never widen them.
                }
            }
            mapped
        } else {
            virtual_tags.iter().map(|tag| json!(tag)).collect()
        };
        set_client_owned_xray_field(rule.as_object_mut()?, "inboundTag", json!(scope));
        adapter_rules.push(rule);
    }
    adapter_rules.push(json!({"type":"field","inboundTag":virtual_tags,"outboundTag":default_tag,"ruleTag":own("provider-default")}));
    outbounds.extend([direct_outbound, block_outbound]);
    let map = config.as_object_mut()?;
    set_client_owned_xray_field(map, "inbounds", json!(inbounds));
    set_client_owned_xray_field(map, "outbounds", json!(outbounds));
    let routing = map.entry("routing").or_insert(json!({})).as_object_mut()?;
    routing
        .entry("domainStrategy")
        .or_insert(json!(domain_strategy));
    set_client_owned_xray_field(routing, "rules", json!(adapter_rules));
    // Client-owned listeners and log sinks are explicit runtime adapter boundaries.
    let log = map.entry("log").or_insert(json!({})).as_object_mut()?;
    for (key, value) in log_object.as_object()? {
        set_client_owned_xray_field(log, key, value.clone());
    }
    set_client_owned_xray_field(log, "access", json!("none"));
    map.entry("dns").or_insert(
        json!({"queryStrategy":dns_query_strategy,"servers":["1.1.1.1","8.8.8.8","localhost"]}),
    );
    let api = map.entry("api").or_insert(json!({})).as_object_mut()?;
    set_client_owned_xray_field(api, "tag", json!(api_tag));
    api.retain(|name, _| !xray_json_field_matches(name, "listen"));
    if api.iter().any(|(name, value)| {
        xray_json_field_matches(name, "services")
            && !value.is_null()
            && !value
                .as_array()
                .is_some_and(|services| services.iter().all(Value::is_string))
    }) {
        return None;
    }
    // Provider API handlers are not capabilities of this client-owned listener.
    // StatsService is the only consumer used by VKarmani.
    set_client_owned_xray_field(api, "services", json!(["StatsService"]));
    merge_stats_policy(&mut config);
    Some(config)
}

#[cfg(test)]
pub(crate) fn build_xray_config(
    template: &RuntimeTemplate,
    network_mode: &str,
    ip_stack: &str,
    send_through_ip: Option<&str>,
    split_tunnel_entries: &[SplitTunnelEntryPayload],
    routing_exclusions: Option<&RoutingExclusionSettingsPayload>,
    runtime_log_path: Option<&Path>,
) -> Result<(Value, SplitTunnelRulePlan, RoutingExclusionRulePlan), String> {
    build_xray_config_with_plan(
        template,
        network_mode,
        ip_stack,
        send_through_ip,
        if network_mode == "tun" {
            Some(build_split_tunnel_rule_plan(split_tunnel_entries)?)
        } else {
            None
        },
        routing_exclusions,
        runtime_log_path,
    )
}

pub(crate) fn build_xray_config_with_plan(
    template: &RuntimeTemplate,
    network_mode: &str,
    ip_stack: &str,
    send_through_ip: Option<&str>,
    prepared_policy: Option<SplitTunnelRulePlan>,
    routing_exclusions: Option<&RoutingExclusionSettingsPayload>,
    runtime_log_path: Option<&Path>,
) -> Result<(Value, SplitTunnelRulePlan, RoutingExclusionRulePlan), String> {
    let plan = if network_mode == "tun" {
        prepared_policy.ok_or("POLICY_PLAN_REQUIRED")?
    } else {
        SplitTunnelRulePlan {
            process_matches: Vec::new(),
            direct_process_matches: Vec::new(),
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
            set_client_owned_xray_field(map, "sendThrough", Value::String(ip.to_string()));
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

        if !plan.direct_process_matches.is_empty() {
            routing_rules.push(json!({"inboundTag":["tun-in"],"process":plan.direct_process_matches,"outboundTag":"direct","ruleTag":"tun-explicit-direct-processes"}));
        }

        if !plan.process_matches.is_empty() {
            routing_rules.push(json!({
                "inboundTag": ["tun-in"],
                "process": plan.process_matches.clone(),
                "outboundTag": "proxy",
                "ruleTag": "tun-selected-processes"
            }));
        }
        if ip_stack == "ipv4" && !plan.process_matches.is_empty() {
            let selected_index = routing_rules
                .iter()
                .position(|r| r["ruleTag"] == "tun-selected-processes")
                .expect("selected rule");
            routing_rules.insert(selected_index, json!({"inboundTag":["tun-in"],"process":plan.process_matches.clone(),"ip":["::/0"],"outboundTag":"block","ruleTag":"tun-selected-ipv6-guard"}));
        }
        routing_rules.push(json!({"inboundTag":["tun-in"],"outboundTag":"direct","ruleTag":"tun-unselected-direct"}));
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

    let log_object = if runtime_log_path.is_some() {
        json!({
            "loglevel": "error",
            "error": "",
            "access": ""
        })
    } else {
        json!({
            "loglevel": "error"
        })
    };

    let dns_query_strategy = if ip_stack == "ipv6" {
        "UseIPv6"
    } else {
        "UseIPv4"
    };

    if let Some(full_config) = template.full_config.as_ref() {
        let block_outbound = json!({
            "tag": "block",
            "protocol": "blackhole",
            "settings": {}
        });

        if let Some(full_runtime_config) = build_from_full_xray_config_template(
            template,
            full_config,
            inbounds.clone(),
            routing_rules.clone(),
            direct_outbound.clone(),
            block_outbound,
            FullConfigAdapterSettings {
                log_object: log_object.clone(),
                domain_strategy,
                dns_query_strategy,
                send_through_ip,
            },
        ) {
            return Ok((full_runtime_config, plan, routing_exclusion_plan));
        }
        return Err("Не удалось применить client adapter к полному Xray config; неполный fallback запрещён.".into());
    }

    Ok((
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
    ))
}

pub(crate) fn value_as_valid_port(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .map(|port| port as u16)
}

pub(crate) fn extract_outbound_address_and_port(
    template: &RuntimeTemplate,
) -> (Option<String>, u16) {
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

pub(crate) fn resolve_ipv4_addresses(host: &str, port: u16) -> Vec<String> {
    let mut addresses = Vec::new();

    if let Ok(items) = resolve_socket_addresses(host, port) {
        for addr in items {
            if !addr.ip().is_ipv4() {
                continue;
            }

            let ip = addr.ip().to_string();
            if !addresses.iter().any(|item| item == &ip) {
                addresses.push(ip);
            }
        }
    }

    addresses
}

#[cfg(target_os = "windows")]
pub(crate) fn default_route_snapshot() -> Result<DefaultRouteSnapshot, String> {
    let raw = run_powershell(
        r#"
$ErrorActionPreference = 'Stop'
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore |
  Where-Object { $_.State -eq 'Alive' -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'vkarmani-tun' } |
  Sort-Object @{Expression={ $_.RouteMetric + $_.InterfaceMetric }} | Select-Object -First 1
if (-not $route) { throw 'No original default route' }
$adapter = Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex } | Select-Object -First 1
if ($adapter.Status -ne 'Up') { throw 'Default adapter not Up' }
$address = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
  Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
if (-not $address) { throw 'No preferred source IPv4' }
@{ InterfaceIndex=$route.InterfaceIndex; NextHop=$route.NextHop; InterfaceAlias=$route.InterfaceAlias; SourceIp=$address.IPAddress } | ConvertTo-Json -Compress
"#,
    )?;
    let route: DefaultRouteSnapshot =
        serde_json::from_str(&raw).map_err(|_| "Invalid default route snapshot".to_string())?;
    if route.interface_index == 0
        || route.interface_alias.is_empty()
        || route.interface_alias == TUN_INTERFACE_NAME
        || route.source_ip.parse::<Ipv4Addr>().is_err()
        || route.next_hop.parse::<Ipv4Addr>().is_err()
    {
        return Err("TUN_BINDING_INVALID: original interface/source address not confirmed".into());
    }
    Ok(route)
}

pub(crate) fn bind_tun_outbounds(config: &mut Value, interface: &str) -> Result<(), String> {
    if interface.is_empty()
        || interface == TUN_INTERFACE_NAME
        || interface.len() > 256
        || interface.contains('\0')
    {
        return Err("TUN_BINDING_INVALID: invalid outbound interface".into());
    }
    let inbounds = config["inbounds"]
        .as_array_mut()
        .ok_or("Missing TUN inbounds")?;
    for inbound in inbounds.iter_mut().filter(|v| v["protocol"] == "tun") {
        inbound["settings"]["autoOutboundsInterface"] = json!(interface);
    }
    for outbound in config["outbounds"]
        .as_array_mut()
        .ok_or("Missing TUN outbounds")?
    {
        if matches!(
            outbound["protocol"].as_str(),
            Some("blackhole" | "loopback")
        ) {
            continue;
        }
        let map = outbound.as_object_mut().ok_or("Missing outbound object")?;
        let stream = map
            .entry("streamSettings")
            .or_insert(json!({}))
            .as_object_mut()
            .ok_or("Incompatible TUN stream settings")?;
        let sockopt = stream
            .entry("sockopt")
            .or_insert(json!({}))
            .as_object_mut()
            .ok_or("Incompatible TUN socket settings")?;
        if sockopt
            .get("interface")
            .is_some_and(|v| v.as_str() != Some(interface))
        {
            return Err(
                "TUN_BINDING_CONFLICT: provider interface conflicts with client adapter".into(),
            );
        }
        sockopt.insert("interface".into(), json!(interface));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn find_tun_interface_index(interface_name: &str) -> Result<u32, String> {
    owned_interface_index(interface_name)
}

#[cfg(target_os = "windows")]
pub(crate) fn wait_for_tun_interface(interface_name: &str) -> Result<u32, String> {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Ok(index) = find_tun_interface_index(interface_name) {
            return Ok(index);
        }
        if Instant::now() >= deadline {
            return Err("TUN interface deadline exceeded".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tun_policy_tests {
    use super::*;
    #[cfg(target_os = "windows")]
    #[test]
    fn original_default_route_snapshot_is_read_only() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let snapshot = default_route_snapshot().expect("Read-only original route snapshot");
        assert!(snapshot.interface_index > 0);
        assert_ne!(snapshot.interface_alias, TUN_INTERFACE_NAME);
        assert!(snapshot.source_ip.parse::<Ipv4Addr>().is_ok());
    }
    #[test]
    fn selected_vpn_unselected_direct_and_explicit_physical_binding() {
        let template = RuntimeTemplate {
            family: "xray".into(),
            protocol: "vless".into(),
            outbound: json!({"protocol":"vless","settings":{"vnext":[{"address":"vpn.example","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}]}}),
            remarks: None,
            full_config: None,
            primary_outbound_tag: None,
            profile_kind: None,
        };
        let entries = vec![SplitTunnelEntryPayload {
            kind: "app".into(),
            value: "example.exe".into(),
            enabled: true,
            policy: None,
        }];
        let (mut config, _, _) = build_xray_config(
            &template,
            "tun",
            "ipv4",
            Some("192.0.2.20"),
            &entries,
            None,
            None,
        )
        .unwrap();
        bind_tun_outbounds(&mut config, "Ethernet").unwrap();
        let rules = config["routing"]["rules"].as_array().unwrap();
        let selected = rules
            .iter()
            .find(|r| r["ruleTag"] == "tun-selected-processes")
            .unwrap();
        assert_eq!(selected["outboundTag"], "proxy");
        let direct = rules
            .iter()
            .find(|r| r["ruleTag"] == "tun-unselected-direct")
            .unwrap();
        assert_eq!(direct["outboundTag"], "direct");
        assert!(direct.get("process").is_none());
        let ipv6 = rules
            .iter()
            .find(|r| r["ruleTag"] == "tun-selected-ipv6-guard")
            .unwrap();
        assert_eq!(ipv6["process"], selected["process"]);
        assert!(!rules.iter().any(|r| r["ruleTag"] == "tun-ipv6-leak-guard"
            || r["ruleTag"] == "tun-unselected-public-block"));
        assert_eq!(
            config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["protocol"] == "tun")
                .unwrap()["settings"]["autoOutboundsInterface"],
            "Ethernet"
        );
        assert!(config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["protocol"] != "blackhole")
            .all(|o| o["streamSettings"]["sockopt"]["interface"] == "Ethernet"));
        assert!(bind_tun_outbounds(&mut config, TUN_INTERFACE_NAME).is_err());
        assert!(bind_tun_outbounds(&mut config, "Wi-Fi")
            .unwrap_err()
            .starts_with("TUN_BINDING_CONFLICT"));
    }
}
