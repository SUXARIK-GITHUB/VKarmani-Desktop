use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WindowsServiceInfo {
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) exe_path: String,
    pub(crate) process_id: u32,
    pub(crate) state: String,
    #[serde(default)]
    service_type: String,
    #[serde(default)]
    pub(crate) supported: bool,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}
fn classify_services(mut services: Vec<WindowsServiceInfo>) -> Vec<WindowsServiceInfo> {
    let mut paths = std::collections::HashMap::<String, usize>::new();
    let mut pids = std::collections::HashMap::<u32, usize>::new();
    for service in &services {
        let key = normalize_process_match(&service.exe_path)
            .unwrap_or_default()
            .to_lowercase();
        *paths.entry(key).or_default() += 1;
        if service.process_id != 0 {
            *pids.entry(service.process_id).or_default() += 1;
        }
    }
    for service in &mut services {
        let key = normalize_process_match(&service.exe_path)
            .unwrap_or_default()
            .to_lowercase();
        let file = key.rsplit('/').next().unwrap_or_default();
        let own_process = service.service_type.eq_ignore_ascii_case("Own Process");
        let shared_pid = pids
            .get(&service.process_id)
            .is_some_and(|count| *count > 1);
        let shared_exe = paths.get(&key).is_some_and(|count| *count > 1);
        service.supported = own_process
            && !shared_pid
            && !shared_exe
            && !matches!(file, "svchost.exe" | "services.exe")
            && validate_app_identity(&service.exe_path).is_ok();
        service.reason = if service.supported {
            None
        } else {
            Some("SERVICE_SHARED_OR_UNSUPPORTED".into())
        };
    }
    services
}
pub(crate) fn service_inventory() -> Result<Vec<WindowsServiceInfo>, String> {
    #[cfg(target_os = "windows")]
    {
        let raw = run_powershell(
            r#"
$ErrorActionPreference = 'Stop'
$items = @(Get-CimInstance Win32_Service | Select-Object -First 2049)
if ($items.Count -gt 2048) { throw 'Service inventory limit' }
$result = @($items | ForEach-Object {
  $command = [Environment]::ExpandEnvironmentVariables([string]$_.PathName)
  $exe = ''
  if ($command -match '^\s*"([^"\r\n]+?\.exe)"') { $exe = $Matches[1] }
  elseif ($command -match '^\s*([^\r\n]+?\.exe)(\s|$)') { $exe = $Matches[1] }
  @{ name=[string]$_.Name; displayName=[string]$_.DisplayName; exePath=$exe; processId=[uint32]$_.ProcessId; state=[string]$_.State; serviceType=[string]$_.ServiceType }
})
ConvertTo-Json -InputObject $result -Depth 3 -Compress
"#,
        )?;
        if raw.len() > 2 * 1024 * 1024 {
            return Err("SERVICE_INVENTORY_LIMIT".into());
        }
        let services: Vec<WindowsServiceInfo> =
            serde_json::from_str(&raw).map_err(|_| "SERVICE_INVENTORY_INVALID".to_string())?;
        if services.len() > 2048 {
            return Err("SERVICE_INVENTORY_LIMIT".into());
        }
        Ok(classify_services(services))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Windows services unavailable".into())
    }
}
#[tauri::command]
pub(crate) async fn list_windows_services() -> Result<Vec<WindowsServiceInfo>, String> {
    tauri::async_runtime::spawn_blocking(service_inventory)
        .await
        .map_err(|_| "Service inventory interrupted".to_string())?
}

fn validate_app_identity(value: &str) -> Result<String, String> {
    if value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(
            "RULE_INVALID: executable identity is empty, oversized or contains controls".into(),
        );
    }
    let trimmed = value.trim();
    let executable = if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest
            .find('"')
            .ok_or("RULE_INVALID: unclosed executable quote")?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() && !suffix.starts_with(char::is_whitespace) {
            return Err("RULE_INVALID: malformed quoted executable".into());
        }
        rest[..end].to_string()
    } else {
        let lower = trimmed.to_ascii_lowercase();
        let end = lower
            .match_indices(".exe")
            .find(|(i, _)| {
                trimmed[i + 4..].is_empty() || trimmed[i + 4..].starts_with(char::is_whitespace)
            })
            .map(|(i, _)| i + 4)
            .unwrap_or(trimmed.len());
        trimmed[..end].to_string()
    }
    .replace('\\', "/");
    if executable.is_empty()
        || !executable.to_lowercase().ends_with(".exe")
        || executable.contains(['*', '?', '<', '>', '|', '"', '%'])
        || (!executable.contains('/') && executable.contains(':'))
        || executable
            .split('/')
            .any(|s| s.is_empty() || matches!(s, "." | "..") || s.ends_with(['.', ' ']))
    {
        return Err("RULE_INVALID: expected exe name or absolute Windows exe path".into());
    }
    if executable.contains('/')
        && (executable.len() < 4
            || !executable.as_bytes()[0].is_ascii_alphabetic()
            || !executable[1..].starts_with(":/")
            || executable[2..].contains(':'))
    {
        return Err("RULE_INVALID: absolute Windows path required".into());
    }
    Ok(executable)
}
fn policy_error(index: usize, entry: &SplitTunnelEntryPayload, reason: &str) -> String {
    // Only a bounded basename is exposed, never a private absolute path/config.
    let value = entry.value.replace('\\', "/");
    let identity = value.rsplit('/').next().unwrap_or("[invalid]");
    let identity = if identity.chars().count() <= 64
        && identity
            .chars()
            .all(|c| c.is_alphanumeric() || "_. -".contains(c))
    {
        identity
    } else {
        "[invalid]"
    };
    format!(
        "{reason}; rule #{}; target={}; identity={identity}",
        index + 1,
        if entry.kind == "service" {
            "service"
        } else {
            "application"
        }
    )
}

fn identities_overlap(left: &str, right: &str) -> bool {
    let (left, right) = (left.to_lowercase(), right.to_lowercase());
    left == right
        || ((!left.contains('/') || !right.contains('/'))
            && left.rsplit('/').next() == right.rsplit('/').next())
}
pub(crate) fn build_policy_plan(
    entries: &[SplitTunnelEntryPayload],
    services: &[WindowsServiceInfo],
) -> Result<SplitTunnelRulePlan, String> {
    if entries.len() > 256 {
        return Err("RULE_LIMIT: maximum256 rules".into());
    }
    let mut plan = SplitTunnelRulePlan {
        process_matches: vec![],
        direct_process_matches: vec![],
        resolved_apps: 0,
        resolved_services: 0,
        skipped_notes: vec![],
        default_vpn: false,
    };
    let mut identities: Vec<(String, String)> = vec![];
    for (index, entry) in entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.enabled)
    {
        let policy = entry.policy.as_deref().unwrap_or("VPN");
        if !matches!(policy, "VPN" | "DIRECT") {
            return Err(policy_error(index, entry, "RULE_POLICY_UNSUPPORTED"));
        }
        let identity = match entry.kind.as_str() {
            "app" => {
                validate_app_identity(&entry.value).map_err(|e| policy_error(index, entry, &e))?
            }
            "service" => {
                if entry.value.len() > 256 || entry.value.chars().any(char::is_control) {
                    return Err(policy_error(
                        index,
                        entry,
                        "RULE_INVALID: invalid service identity",
                    ));
                }
                let service = services
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(entry.value.trim()))
                    .ok_or_else(|| policy_error(index, entry, "SERVICE_NOT_FOUND"))?;
                if !service.supported {
                    return Err(policy_error(
                        index,
                        entry,
                        "SERVICE_SHARED_OR_UNSUPPORTED: service-aware routing unavailable",
                    ));
                }
                validate_app_identity(&service.exe_path)
                    .map_err(|e| policy_error(index, entry, &e))?
            }
            _ => return Err(policy_error(index, entry, "RULE_TARGET_UNSUPPORTED")),
        };
        if identities.iter().any(|(other, other_policy)| {
            other_policy != policy && identities_overlap(other, &identity)
        }) {
            return Err("RULE_CONFLICT: overlapping VPN/DIRECT identities".into());
        }
        if identities
            .iter()
            .any(|(other, _)| other.eq_ignore_ascii_case(&identity))
        {
            continue;
        }
        identities.push((identity.clone(), policy.into()));
        let target = if policy == "DIRECT" {
            &mut plan.direct_process_matches
        } else {
            &mut plan.process_matches
        };
        for candidate in process_match_candidates(&identity) {
            push_unique_process_match(target, candidate);
        }
        if entry.kind == "app" {
            plan.resolved_apps += 1;
        } else {
            plan.resolved_services += 1;
        }
    }
    Ok(plan)
}
pub(crate) fn active_policy_entries(
    entries: &[SplitTunnelEntryPayload],
    mode: &str,
) -> Result<Vec<SplitTunnelEntryPayload>, String> {
    if !matches!(mode, "all" | "selected" | "exclude") {
        return Err("RULE_MODE_UNSUPPORTED".into());
    }
    Ok(entries
        .iter()
        .filter(|e| {
            e.enabled
                && (mode == "selected" || e.policy.as_deref() != Some("VPN") && e.policy.is_some())
        })
        .cloned()
        .collect())
}
pub(crate) fn build_split_tunnel_rule_plan_for_mode(
    entries: &[SplitTunnelEntryPayload],
    mode: &str,
) -> Result<SplitTunnelRulePlan, String> {
    let active = active_policy_entries(entries, mode)?;
    let services = if active.iter().any(|e| e.kind == "service") {
        service_inventory()?
    } else {
        vec![]
    };
    let mut plan = build_policy_plan(&active, &services)?;
    if mode == "selected" && plan.process_matches.is_empty() {
        return Err("RULE_SELECTION_EMPTY: selected mode requires an active VPN application/service; choose all applications for ordinary TUN".into());
    }
    plan.default_vpn = mode != "selected";
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(value: &str, policy: &str) -> SplitTunnelEntryPayload {
        SplitTunnelEntryPayload {
            kind: "app".into(),
            value: value.into(),
            enabled: true,
            policy: Some(policy.into()),
        }
    }
    fn service(name: &str, exe: &str, pid: u32, kind: &str) -> WindowsServiceInfo {
        WindowsServiceInfo {
            name: name.into(),
            display_name: name.into(),
            exe_path: exe.into(),
            process_id: pid,
            state: "Running".into(),
            service_type: kind.into(),
            supported: false,
            reason: None,
        }
    }
    #[test]
    fn full_paths_do_not_expand_to_same_name_executables() {
        let plan = build_policy_plan(
            &[
                entry("C:/A/app.exe", "VPN"),
                entry("D:/B/app.exe", "DIRECT"),
            ],
            &[],
        )
        .unwrap();
        assert!(plan
            .process_matches
            .iter()
            .all(|p| p.contains('/') || p.contains('\\')));
        assert!(plan
            .direct_process_matches
            .iter()
            .all(|p| p.contains('/') || p.contains('\\')));
        assert!(build_policy_plan(
            &[entry("C:/A/app.exe", "VPN"), entry("app.exe", "DIRECT")],
            &[]
        )
        .is_err());
        assert!(build_policy_plan(&[entry("app.exe", "BLOCK")], &[]).is_err());
    }
    #[test]
    fn service_shared_pid_type_exe_and_svchost_are_refused() {
        let services = classify_services(vec![
            service("A", "C:/Svc/a.exe", 1, "Own Process"),
            service("B", "C:/Svc/b.exe", 2, "Share Process"),
            service("C", "C:/Svc/c.exe", 3, "Own Process"),
            service("D", "C:/Svc/d.exe", 3, "Own Process"),
            service("E", "C:/Svc/shared.exe", 4, "Own Process"),
            service("F", "C:/Svc/shared.exe", 5, "Own Process"),
            service("G", "C:/Windows/svchost.exe", 6, "Own Process"),
        ]);
        assert!(services[0].supported);
        assert!(services[1..].iter().all(|s| !s.supported));
        let mut selected = entry("B", "VPN");
        selected.kind = "service".into();
        assert!(build_policy_plan(&[selected.clone()], &services)
            .unwrap_err()
            .starts_with("SERVICE_SHARED"));
        selected.value = "A".into();
        let plan = build_policy_plan(&[selected], &services).unwrap();
        assert_eq!(plan.resolved_services, 1);
    }
    #[test]
    fn rule_bounds_unknown_target_and_disabled_entries() {
        let disabled = SplitTunnelEntryPayload {
            enabled: false,
            ..entry("../evil.exe", "VPN")
        };
        assert!(build_policy_plan(&[disabled], &[])
            .unwrap()
            .process_matches
            .is_empty());
        let mut bad = entry("app.exe", "VPN");
        bad.kind = "folder".into();
        assert!(build_policy_plan(&[bad], &[]).is_err());
        assert!(build_policy_plan(&vec![entry("app.exe", "VPN"); 257], &[]).is_err());
        assert!(build_policy_plan(&[entry("C:/A/../app.exe", "VPN")], &[]).is_err());
    }
    fn fixture_entries(name: &str) -> Vec<SplitTunnelEntryPayload> {
        let text = match name {
            "old" => include_str!("../../tests/fixtures/policies/overwritten-072.json"),
            _ => include_str!("../../tests/fixtures/policies/normalized-upgrade.json"),
        };
        serde_json::from_value(
            serde_json::from_str::<Value>(text).unwrap()["splitTunnelEntries"].clone(),
        )
        .unwrap()
    }
    #[test]
    fn persisted_upgrade_full_frontend_wire_to_native_plan() {
        let old = fixture_entries("old");
        let failure = build_policy_plan(&old, &[]).unwrap_err();
        assert!(failure.starts_with("RULE_INVALID: expected exe name or absolute Windows exe path"));
        assert!(failure.contains("rule #3"));
        let migrated = fixture_entries("new");
        let plan = build_split_tunnel_rule_plan_for_mode(&migrated, "selected").unwrap();
        assert_eq!(plan.resolved_apps, 3);
        assert!(plan.process_matches.contains(&"Discord".into()));
        assert!(plan.process_matches.contains(&"backgroundTaskHost".into()));
        assert!(!plan.default_vpn);
        assert_eq!(migrated.len(), 5); // Quarantined intent is retained, disabled.
    }
    #[test]
    fn valid_windows_identity_matrix_keeps_paths_exact() {
        for value in [
            "chrome.exe",
            "telegram.exe",
            "C:/Program Files/App/App.exe",
            "C:/Program Files (x86)/App/App.exe",
            "C:/Пользователи/Юзер/Программа/App.EXE",
            "multi.part.name.exe",
            "C:/folder.exe/app.exe",
        ] {
            assert_eq!(validate_app_identity(value).unwrap(), value);
            let plan = build_policy_plan(&[entry(value, "VPN")], &[]).unwrap();
            if value.contains('/') {
                assert!(plan
                    .process_matches
                    .iter()
                    .all(|p| p.contains('/') || p.contains('\\')));
            }
        }
        assert_eq!(
            validate_app_identity(r#" "C:\Program Files\A\app.exe" --flag "#).unwrap(),
            "C:/Program Files/A/app.exe"
        );
        let long = format!("C:/{}/app.exe", "long".repeat(100));
        assert!(validate_app_identity(&long).is_ok());
    }
    #[test]
    fn invalid_active_identity_matrix_is_strict_and_diagnostics_hide_parent_path() {
        for value in [
            "",
            "   ",
            "C:/Program Files/App/",
            "C:/not-an-executable.txt",
            "relative/path.exe",
            "1:/app.exe",
            "C::/app.exe",
            "a?.exe",
            "https://example.test/app.exe",
            "Service Display Name",
            "[object Object]",
            "null",
            "undefined",
            "\"C:/unclosed.exe",
            "C:/A/../app.exe",
            "C:/bad//app.exe",
            "app.exe\nargs",
        ] {
            assert!(
                build_policy_plan(&[entry(value, "VPN")], &[]).is_err(),
                "{value}"
            );
        }
        let error = build_policy_plan(&[entry("C:/Users/PrivateUser/invalid.txt", "DIRECT")], &[])
            .unwrap_err();
        assert!(error.contains("application") && error.contains("invalid.txt"));
        assert!(!error.contains("PrivateUser"));
    }
    #[test]
    fn all_selected_exclude_active_and_inactive_policy_matrix() {
        let entries = [
            entry("<invalid stored policy>", "VPN"),
            entry("chrome.exe", "DIRECT"),
        ];
        for mode in ["all", "exclude"] {
            let plan = build_split_tunnel_rule_plan_for_mode(&entries, mode).unwrap();
            assert!(plan.default_vpn && plan.process_matches.is_empty());
            assert!(!plan.direct_process_matches.is_empty());
        }
        assert!(build_split_tunnel_rule_plan_for_mode(&entries, "selected").is_err());
        for mode in ["all", "exclude"] {
            let plan = build_split_tunnel_rule_plan_for_mode(&[], mode).unwrap();
            assert!(plan.default_vpn);
        }
        assert!(build_split_tunnel_rule_plan_for_mode(&[], "selected")
            .unwrap_err()
            .starts_with("RULE_SELECTION_EMPTY"));
        assert!(build_split_tunnel_rule_plan_for_mode(&[], "unknown").is_err());
        assert!(
            build_split_tunnel_rule_plan_for_mode(&[entry("../bad.exe", "DIRECT")], "all").is_err()
        );
        let stale_service = SplitTunnelEntryPayload {
            kind: "service".into(),
            ..entry("RemovedService", "VPN")
        };
        assert!(build_split_tunnel_rule_plan_for_mode(&[stale_service], "all").is_ok());
    }
    #[test]
    fn removed_exe_and_duplicates_are_pure_identity_not_filesystem_checks() {
        let plan = build_policy_plan(
            &[
                entry("C:/Removed/App.exe", "VPN"),
                entry("C:/Removed/App.exe", "VPN"),
                entry("D:/Other/App.exe", "DIRECT"),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(plan.resolved_apps, 2);
        assert!(!plan.process_matches.contains(&"App".into()));
        assert!(build_policy_plan(
            &[
                entry("App.exe", "DIRECT"),
                entry("C:/Removed/App.exe", "VPN")
            ],
            &[]
        )
        .is_err());
    }
    #[test]
    fn current_mode_xray_policy_plan_is_generated_before_any_network_mutation() {
        let template:RuntimeTemplate=serde_json::from_value(json!({"family":"xray","protocol":"vless","outbound":{"protocol":"vless","settings":{"vnext":[{"address":"example.test","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001"}]}]}}})).unwrap();
        for mode in ["all", "exclude", "selected"] {
            let plan = build_split_tunnel_rule_plan_for_mode(
                &[entry("chrome.exe", "DIRECT"), entry("telegram.exe", "VPN")],
                mode,
            )
            .unwrap();
            let (config, _, _) = build_xray_config_with_plan(
                &template,
                "tun",
                "ipv4",
                Some("192.0.2.1"),
                Some(plan),
                None,
                None,
            )
            .unwrap();
            let rules = config["routing"]["rules"].as_array().unwrap();
            assert!(rules
                .iter()
                .any(|r| r["ruleTag"] == "tun-explicit-direct-processes"));
            let fallback = rules
                .iter()
                .find(|r| {
                    r["ruleTag"]
                        == if mode == "selected" {
                            "tun-unselected-direct"
                        } else {
                            "tun-all-vpn"
                        }
                })
                .unwrap();
            assert_eq!(
                fallback["outboundTag"],
                if mode == "selected" {
                    "direct"
                } else {
                    "proxy"
                }
            );
            assert_eq!(
                rules
                    .iter()
                    .any(|r| r["ruleTag"] == "tun-selected-processes"),
                mode == "selected"
            );
        }
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn real_service_inventory_is_read_only() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let services = service_inventory().unwrap();
        assert!(!services.is_empty());
        assert!(services.len() <= 2048);
    }
}
