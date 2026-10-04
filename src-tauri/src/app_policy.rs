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
        return Err("RULE_INVALID".into());
    }
    let executable = extract_executable_value(value).replace('\\', "/");
    if executable.is_empty()
        || !executable.to_lowercase().ends_with(".exe")
        || executable.contains(['*', '?', '<', '>', '|', '"', '%'])
        || executable.contains("//")
        || (!executable.contains('/') && executable.contains(':'))
        || executable.split('/').any(|s| matches!(s, "." | ".."))
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
    };
    let mut identities: Vec<(String, String)> = vec![];
    for entry in entries.iter().filter(|entry| entry.enabled) {
        let policy = entry.policy.as_deref().unwrap_or("VPN");
        if !matches!(policy, "VPN" | "DIRECT") {
            return Err("RULE_POLICY_UNSUPPORTED".into());
        }
        let identity = match entry.kind.as_str() {
            "app" => validate_app_identity(&entry.value)?,
            "service" => {
                if entry.value.len() > 256 || entry.value.chars().any(char::is_control) {
                    return Err("RULE_INVALID".into());
                }
                let service = services
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(entry.value.trim()))
                    .ok_or("SERVICE_NOT_FOUND")?;
                if !service.supported {
                    return Err(
                        "SERVICE_SHARED_OR_UNSUPPORTED: service-aware routing unavailable".into(),
                    );
                }
                validate_app_identity(&service.exe_path)?
            }
            _ => return Err("RULE_TARGET_UNSUPPORTED".into()),
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
pub(crate) fn build_split_tunnel_rule_plan(
    entries: &[SplitTunnelEntryPayload],
) -> Result<SplitTunnelRulePlan, String> {
    let services = if entries.iter().any(|e| e.enabled && e.kind == "service") {
        service_inventory()?
    } else {
        vec![]
    };
    build_policy_plan(entries, &services)
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
    #[cfg(target_os = "windows")]
    #[test]
    fn real_service_inventory_is_read_only() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let services = service_inventory().unwrap();
        assert!(!services.is_empty());
        assert!(services.len() <= 2048);
    }
}
