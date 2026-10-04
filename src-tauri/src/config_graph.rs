use super::*;
use std::collections::{BTreeSet, HashMap, HashSet};

fn graph_error(path: &str) -> String {
    format!("Некорректный Xray config graph: {path}")
}

fn tag_field<'a>(value: &'a Value, key: &str, path: &str) -> Result<Option<&'a str>, String> {
    match value.get(key) {
        None => Ok(None),
        Some(Value::String(tag)) if tag.is_empty() => Ok(None),
        Some(Value::String(tag))
            if !tag.trim().is_empty() && !tag.chars().any(char::is_control) =>
        {
            Ok(Some(tag))
        }
        _ => Err(graph_error(path)),
    }
}

fn array_field<'a>(value: &'a Value, key: &str, path: &str) -> Result<&'a [Value], String> {
    match value.get(key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        _ => Err(graph_error(path)),
    }
}

fn check_reference<'a>(
    value: &'a Value,
    key: &str,
    tags: &BTreeSet<&str>,
    path: &str,
) -> Result<Option<&'a str>, String> {
    let tag = tag_field(value, key, path)?;
    if tag.is_some_and(|tag| !tags.contains(tag)) {
        return Err(graph_error(path));
    }
    Ok(tag)
}

fn visit_dialer<'a>(
    tag: &'a str,
    edges: &HashMap<&'a str, Vec<&'a str>>,
    visiting: &mut HashSet<&'a str>,
    done: &mut HashSet<&'a str>,
) -> Result<(), String> {
    if visiting.contains(tag) {
        return Err(graph_error("outbound dialer cycle"));
    }
    if done.contains(tag) {
        return Ok(());
    }
    visiting.insert(tag);
    if let Some(targets) = edges.get(tag) {
        for target in targets {
            visit_dialer(target, edges, visiting, done)?;
        }
    }
    visiting.remove(tag);
    done.insert(tag);
    Ok(())
}

pub(crate) fn validate_full_config_graph(config: &Value) -> Result<(), String> {
    if !config.is_object() {
        return Err(graph_error("config object"));
    }
    for section in ["log", "api", "policy", "stats", "dns"] {
        if config
            .get(section)
            .is_some_and(|value| !value.is_object() && !value.is_null())
        {
            return Err(graph_error(section));
        }
    }
    let outbounds = array_field(config, "outbounds", "outbounds array")?;
    if outbounds.is_empty() || outbounds.len() > 1000 {
        return Err(graph_error("outbounds count"));
    }
    let mut tags = BTreeSet::new();
    for (index, outbound) in outbounds.iter().enumerate() {
        if !outbound.is_object()
            || outbound
                .get("protocol")
                .and_then(Value::as_str)
                .map_or(true, str::is_empty)
        {
            return Err(graph_error(&format!("outbounds[{index}]")));
        }
        if let Some(tag) = tag_field(outbound, "tag", &format!("outbounds[{index}].tag"))? {
            if !tags.insert(tag) {
                return Err(graph_error(&format!("outbounds[{index}].tag duplicate")));
            }
        }
    }
    let empty = json!({});
    let mut edges = HashMap::new();
    for (index, outbound) in outbounds.iter().enumerate() {
        let mut targets = Vec::new();
        for (source, key) in [
            (
                outbound
                    .pointer("/streamSettings/sockopt")
                    .unwrap_or(&empty),
                "dialerProxy",
            ),
            (outbound.get("proxySettings").unwrap_or(&empty), "tag"),
        ] {
            if let Some(tag) = check_reference(
                source,
                key,
                &tags,
                &format!("outbounds[{index}].dialer reference"),
            )? {
                targets.push(tag);
            }
        }
        if let Some(tag) = outbound.get("tag").and_then(Value::as_str) {
            edges.insert(tag, targets);
        }
    }
    let mut visiting = HashSet::new();
    let mut done = HashSet::new();
    for tag in edges.keys() {
        visit_dialer(tag, &edges, &mut visiting, &mut done)?;
    }
    let routing = config.get("routing").unwrap_or(&empty);
    if !routing.is_object() {
        return Err(graph_error("routing object"));
    }
    let mut balancer_tags = BTreeSet::new();
    for (index, balancer) in array_field(routing, "balancers", "routing.balancers")?
        .iter()
        .enumerate()
    {
        if !balancer.is_object() {
            return Err(graph_error("balancer object"));
        }
        let tag = tag_field(balancer, "tag", "balancer.tag")?
            .ok_or_else(|| graph_error("balancer.tag"))?;
        if !balancer_tags.insert(tag) {
            return Err(graph_error("balancer.tag duplicate"));
        }
        let selectors = array_field(balancer, "selector", "balancer.selector")?;
        if selectors.is_empty() || selectors.iter().any(|value| !value.is_string()) {
            return Err(graph_error("balancer.selector"));
        }
        let has_members = tags.iter().any(|tag| {
            selectors
                .iter()
                .any(|prefix| tag.starts_with(prefix.as_str().unwrap_or_default()))
        });
        let fallback = check_reference(
            balancer,
            "fallbackTag",
            &tags,
            &format!("routing.balancers[{index}].fallbackTag"),
        )?;
        if !has_members && fallback.is_none() {
            return Err(graph_error("balancer.selector matches nothing"));
        }
    }
    if let Some(api) = config.get("api") {
        if let Some(tag) = tag_field(api, "tag", "api.tag")? {
            if !tags.insert(tag) {
                return Err(graph_error("api.tag duplicate outbound"));
            }
        }
    }
    for (index, rule) in array_field(routing, "rules", "routing.rules")?
        .iter()
        .enumerate()
    {
        if !rule.is_object() {
            return Err(graph_error("routing rule object"));
        }
        let outbound = check_reference(
            rule,
            "outboundTag",
            &tags,
            &format!("routing.rules[{index}].outboundTag"),
        )?;
        let balancer = check_reference(
            rule,
            "balancerTag",
            &balancer_tags,
            &format!("routing.rules[{index}].balancerTag"),
        )?;
        if outbound.is_some() == balancer.is_some() {
            return Err(graph_error("routing rule ambiguous/missing target"));
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_template(template: &RuntimeTemplate) -> Result<(), String> {
    if let Some(config) = &template.full_config {
        // IPC callers must pass the same bounded graph checks as subscription parsing.
        if serde_json::to_vec(config)
            .map_err(|_| graph_error("serialization"))?
            .len()
            > 2 * 1024 * 1024
        {
            return Err(graph_error("document byte limit"));
        }
        let mut stack = vec![(config, 0)];
        let mut nodes = 0;
        while let Some((value, depth)) = stack.pop() {
            nodes += 1;
            if nodes > 100000 || depth > 64 {
                return Err(graph_error("document complexity"));
            }
            match value {
                Value::Object(map) => stack.extend(map.values().map(|value| (value, depth + 1))),
                Value::Array(items) => stack.extend(items.iter().map(|value| (value, depth + 1))),
                _ => {}
            }
        }
        validate_full_config_graph(config)?;
        if let Some(tag) = &template.primary_outbound_tag {
            if !array_field(config, "outbounds", "outbounds")?
                .iter()
                .any(|outbound| {
                    outbound.get("tag").and_then(Value::as_str) == Some(tag)
                        && outbound == &template.outbound
                })
            {
                return Err(graph_error("primaryOutboundTag"));
            }
        }
    }
    Ok(())
}

pub(crate) fn verified_template_identity(
    value: &Value,
    canonical: &str,
    claimed_hash: Option<&str>,
) -> Result<(RuntimeTemplate, String), String> {
    if canonical.len() > 4 * 1024 * 1024 {
        return Err("REQUEST_IDENTITY: слишком большой template.".into());
    }
    let supplied: Value = serde_json::from_str(canonical)
        .map_err(|_| "REQUEST_IDENTITY: некорректный canonical template.".to_string())?;
    if &supplied != value {
        return Err("REQUEST_IDENTITY: canonical template не совпадает с runtime payload.".into());
    }
    let hash = sha256_hex_bytes(canonical.as_bytes());
    if claimed_hash != Some(hash.as_str()) {
        return Err("REQUEST_IDENTITY: fingerprint не соответствует runtime payload.".into());
    }
    let template: RuntimeTemplate = serde_json::from_value(value.clone())
        .map_err(|_| "REQUEST_IDENTITY: неверная структура runtime template.".to_string())?;
    validate_runtime_template(&template).map_err(|error| format!("REQUEST_IDENTITY: {error}"))?;
    Ok((template, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap()
    }
    #[test]
    fn renderer_identity_cannot_claim_another_template_or_fingerprint() {
        let value = json!({"family":"xray","protocol":"vless","outbound":fixture()["outbounds"][0],"fullConfig":fixture()});
        let text = serde_json::to_string(&value).unwrap();
        let hash = sha256_hex_bytes(text.as_bytes());
        assert!(verified_template_identity(&value, &text, Some(&hash)).is_ok());
        assert!(verified_template_identity(&value, &text, Some(&"b".repeat(64))).is_err());
        let mut changed = value.clone();
        changed["fullConfig"]["futureExtension"]["unicode"] = json!("changed");
        assert!(verified_template_identity(&changed, &text, Some(&hash)).is_err());
    }
    #[test]
    fn accepts_general_balancer_unknown_fields_and_unchanged_input() {
        let config = fixture();
        let before = config.clone();
        validate_full_config_graph(&config).unwrap();
        assert_eq!(config, before);
    }
    #[test]
    fn rejects_duplicate_tags_missing_targets_selectors_and_cycles() {
        let mut duplicate = fixture();
        duplicate["outbounds"][1]["tag"] = json!("pool-a");
        assert!(validate_full_config_graph(&duplicate).is_err());
        for pointer in [
            "/routing/rules/0/outboundTag",
            "/routing/rules/1/balancerTag",
            "/routing/balancers/0/fallbackTag",
        ] {
            let mut config = fixture();
            *config.pointer_mut(pointer).unwrap() = json!("synthetic-secret");
            let error = validate_full_config_graph(&config).unwrap_err();
            assert!(!error.contains("synthetic-secret"));
        }
        let mut config = fixture();
        config["routing"]["balancers"][0]["selector"] = json!(["absent"]);
        config["routing"]["balancers"][0]["fallbackTag"] = json!("");
        assert!(validate_full_config_graph(&config).is_err());
        config["routing"]["balancers"][0]["fallbackTag"] = json!("pool-b");
        validate_full_config_graph(&config).unwrap();
        config["outbounds"][0]["streamSettings"]["sockopt"] = json!({"dialerProxy":"pool-b"});
        config["outbounds"][1]["streamSettings"]["sockopt"] = json!({"dialerProxy":"pool-a"});
        assert!(validate_full_config_graph(&config)
            .unwrap_err()
            .contains("cycle"));
    }
    #[test]
    fn ipc_rejects_byte_limit_and_missing_primary_before_runtime_side_effects() {
        let mut template = RuntimeTemplate {
            family: "xray".into(),
            protocol: "vless".into(),
            outbound: fixture()["outbounds"][0].clone(),
            remarks: None,
            full_config: Some(fixture()),
            primary_outbound_tag: Some("missing".into()),
            profile_kind: Some("configuration".into()),
        };
        assert!(validate_runtime_template(&template).is_err());
        template.primary_outbound_tag = Some("pool-a".into());
        validate_runtime_template(&template).unwrap();
        template.full_config.as_mut().unwrap()["large"] = json!("x".repeat(2 * 1024 * 1024));
        assert!(validate_runtime_template(&template)
            .unwrap_err()
            .contains("byte limit"));
    }
}
