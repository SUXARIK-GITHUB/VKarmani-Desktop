use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::{TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

const SOCKS_PORT: u16 = 10808;
const HTTP_PORT: u16 = 10809;
const PROXY_BYPASS: &str = "<local>";
const IPIFY_URL: &str = "https://api.ipify.org?format=json";
const APP_USER_AGENT: &str = concat!("VKarmani-Desktop/", env!("CARGO_PKG_VERSION"));
#[cfg(all(target_os = "windows", not(debug_assertions)))]
const STARTUP_REGISTRY_VALUE: &str = "VKarmani Desktop";
const TUN_INTERFACE_NAME: &str = "vkarmani-tun";

struct ManagedCore {
    child: Child,
    core_path: String,
    config_path: String,
    log_path: String,
    server_id: String,
    started_at: String,
    network_mode: String,
    tun_interface_name: Option<String>,
    tun_server_ip: Option<String>,
}

#[derive(Default)]
struct AppState {
    connected: Mutex<bool>,
    active_server_label: Mutex<Option<String>>,
    profile_count: Mutex<usize>,
    last_sync_source: Mutex<Option<String>>,
    runtime: Mutex<Option<ManagedCore>>,
    last_exit_code: Mutex<Option<i32>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapInfo {
    version: String,
    platform: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStatus {
    bridge: String,
    core_installed: bool,
    tunnel_active: bool,
    active_server_label: Option<String>,
    profile_count: Option<usize>,
    last_sync_source: Option<String>,
    message: String,
    core_path: Option<String>,
    config_path: Option<String>,
    log_path: Option<String>,
    launch_mode: String,
    socks_port: Option<u16>,
    http_port: Option<u16>,
    last_prepared_server_id: Option<String>,
    last_prepared_at: Option<String>,
    last_exit_code: Option<i32>,
    system_proxy_enabled: Option<bool>,
    proxy_server: Option<String>,
    proxy_bypass: Option<String>,
    network_mode: Option<String>,
    tun_interface_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyStatus {
    enabled: bool,
    server: Option<String>,
    bypass: Option<String>,
    method: String,
    scope: String,
    checked_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectivityProbe {
    success: bool,
    checked_at: String,
    http_port_open: bool,
    socks_port_open: bool,
    public_ip: Option<String>,
    latency_ms: Option<u128>,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeTemplate {
    family: String,
    protocol: String,
    outbound: Value,
    remarks: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SplitTunnelEntryPayload {
    kind: String,
    value: String,
    enabled: bool,
}

struct SplitTunnelRulePlan {
    process_matches: Vec<String>,
    resolved_apps: usize,
    resolved_services: usize,
    skipped_notes: Vec<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceLookupInfo {
    name: String,
    display_name: String,
    exe_path: String,
    is_shared_host: bool,
}

#[derive(Debug, Deserialize)]
struct IpifyResponse {
    ip: String,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DefaultRouteSnapshot {
    interface_index: u32,
    next_hop: String,
}

fn build_http_client(proxy_url: Option<&str>, timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(false);

    if let Some(proxy_url) = proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|error| format!("Не удалось собрать proxy URL: {error}"))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }

    builder
        .build()
        .map_err(|error| format!("Не удалось создать HTTP client: {error}"))
}

fn fetch_public_ip(client: &reqwest::blocking::Client) -> Result<String, String> {
    let response = client
        .get(IPIFY_URL)
        .header(reqwest::header::USER_AGENT, APP_USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/json, text/plain")
        .send()
        .map_err(|error| format!("Проверка маршрута не прошла: {error}"))?;

    if !response.status().is_success() {
        return Err(format!("IP-сервис вернул HTTP {}", response.status()));
    }

    let payload = response
        .json::<IpifyResponse>()
        .map_err(|error| format!("Не удалось разобрать ответ IP-сервиса: {error}"))?;

    Ok(payload.ip)
}

fn reveal_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn unix_now_string() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default();
    timestamp.to_string()
}

fn log_timestamp_string() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(value) = run_powershell("(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = Command::new("date").args(["+%F %T"]).output() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return value;
            }
        }
    }

    unix_now_string()
}

fn local_day_folder_name() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(value) = run_powershell("(Get-Date).ToString('yyyy-MM-dd')") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = Command::new("date").args(["+%F"]).output() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return value;
            }
        }
    }

    unix_now_string()
}

fn looks_like_launch_root(path: &Path) -> bool {
    path.join("package.json").exists()
        || path.join("START_VKarmani.bat").exists()
        || path.join("resources").exists()
        || path.join("src-tauri").exists()
}

fn looks_like_tauri_subdir(path: &Path) -> bool {
    matches!(path.file_name().and_then(|name| name.to_str()), Some("src-tauri") | Some("target") | Some("debug") | Some("release"))
}

fn normalize_log_base_candidate(path: PathBuf) -> PathBuf {
    let mut candidate = path;

    if matches!(candidate.file_name().and_then(|name| name.to_str()), Some("src-tauri")) {
        if let Some(parent) = candidate.parent() {
            candidate = parent.to_path_buf();
        }
    }

    if matches!(candidate.file_name().and_then(|name| name.to_str()), Some("debug") | Some("release")) {
        if let Some(project_root) = candidate.parent().and_then(|path| path.parent()).and_then(|path| path.parent()) {
            candidate = project_root.to_path_buf();
        }
    } else if matches!(candidate.file_name().and_then(|name| name.to_str()), Some("target")) {
        if let Some(project_root) = candidate.parent().and_then(|path| path.parent()) {
            candidate = project_root.to_path_buf();
        }
    }

    candidate
}

fn push_candidate_dir(candidates: &mut Vec<PathBuf>, value: Option<PathBuf>) {
    if let Some(path) = value {
        let normalized = normalize_log_base_candidate(path);
        if !candidates.iter().any(|item| item == &normalized) {
            candidates.push(normalized);
        }
    }
}

fn app_logs_base_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();

    if let Ok(current_dir) = std::env::current_dir() {
        if looks_like_launch_root(&current_dir) {
            push_candidate_dir(&mut candidates, Some(current_dir.clone()));
        } else if matches!(current_dir.file_name().and_then(|name| name.to_str()), Some("src-tauri")) {
            push_candidate_dir(&mut candidates, current_dir.parent().map(|path| path.to_path_buf()));
        }

        if !looks_like_tauri_subdir(&current_dir) {
            push_candidate_dir(&mut candidates, Some(current_dir));
        }
    }

    if let Ok(executable) = std::env::current_exe() {
        let exe_parent = executable.parent().map(|parent| parent.to_path_buf());
        push_candidate_dir(&mut candidates, exe_parent.clone());

        if let Some(parent) = exe_parent {
            if matches!(parent.file_name().and_then(|name| name.to_str()), Some("debug") | Some("release")) {
                push_candidate_dir(&mut candidates, parent.parent().and_then(|path| path.parent()).and_then(|path| path.parent()).map(|path| path.to_path_buf()));
            }
        }
    }

    push_candidate_dir(&mut candidates, app.path().app_local_data_dir().ok());

    for base in candidates {
        let logs_root = base.join("logs");
        if fs::create_dir_all(&logs_root).is_ok() {
            return Ok(logs_root);
        }
    }

    Err("Не удалось создать logs каталог рядом с приложением или в app data.".to_string())
}

fn daily_log_root(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app_logs_base_dir(app)?.join(local_day_folder_name());
    fs::create_dir_all(&root)
        .map_err(|error| format!("Не удалось создать каталог логов дня: {error}"))?;
    Ok(root)
}

fn interface_logs_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let path = daily_log_root(app)?.join("Interface");
    fs::create_dir_all(&path)
        .map_err(|error| format!("Не удалось создать Interface каталог: {error}"))?;
    Ok(path)
}

fn routing_logs_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let path = daily_log_root(app)?.join("routing");
    fs::create_dir_all(&path)
        .map_err(|error| format!("Не удалось создать routing каталог: {error}"))?;
    Ok(path)
}

fn interface_log_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(interface_logs_dir(app)?.join("interface.log"))
}

fn routing_event_log_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(routing_logs_dir(app)?.join("routing.log"))
}


fn ensure_log_file(path: &PathBuf) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }

    File::create(path)
        .map(|_| ())
        .map_err(|error| format!("Не удалось создать лог-файл {}: {error}", path.display()))
}

fn ensure_log_tree(app: &AppHandle) -> Result<(), String> {
    let interface_path = interface_log_path(app)?;
    let routing_path = routing_event_log_path(app)?;
    let runtime_path = runtime_log_path(app)?;

    ensure_log_file(&interface_path)?;
    ensure_log_file(&routing_path)?;
    ensure_log_file(&runtime_path)?;
    Ok(())
}

fn append_log_line(path: &PathBuf, scope: &str, line: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("Не удалось открыть лог-файл {}: {error}", path.display()))?;

    writeln!(file, "[{}] [{}] {}", log_timestamp_string(), scope, line)
        .map_err(|error| format!("Не удалось записать лог {}: {error}", path.display()))
}

fn append_interface_event(app: &AppHandle, line: &str) -> Result<(), String> {
    let log_path = interface_log_path(app)?;
    append_log_line(&log_path, "INTERFACE", line)
}

fn candidate_core_paths(app: &AppHandle) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_path) = std::env::var("VKARMANI_XRAY_PATH") {
        paths.push(PathBuf::from(env_path));
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        paths.push(resource_dir.join("core").join("windows").join("xray.exe"));
    }

    if let Ok(app_local) = app.path().app_local_data_dir() {
        paths.push(app_local.join("core").join("xray.exe"));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        paths.push(current_dir.join("resources").join("core").join("windows").join("xray.exe"));
        paths.push(current_dir.join("src-tauri").join("bin").join("xray.exe"));
    }

    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            paths.push(parent.join("resources").join("core").join("windows").join("xray.exe"));
        }
    }

    paths
}

fn resolve_core_path(app: &AppHandle) -> Option<PathBuf> {
    candidate_core_paths(app)
        .into_iter()
        .find(|path| path.exists() && path.is_file())
}

fn resolve_core_sidecar_path(core_path: &Path, file_name: &str) -> Option<PathBuf> {
    core_path.parent().map(|dir| dir.join(file_name))
}

fn read_runtime_log_excerpt(path: &Path, lines: usize) -> Vec<String> {
    fs::read_to_string(path)
        .map(|content| {
            content
                .lines()
                .rev()
                .take(lines)
                .map(|line| line.trim().to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn runtime_output_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .or_else(|_| app.path().app_config_dir())
        .map_err(|error| format!("Не удалось определить каталог данных: {error}"))?;

    let path = base.join("runtime");
    fs::create_dir_all(&path).map_err(|error| format!("Не удалось создать runtime каталог: {error}"))?;
    Ok(path)
}

fn runtime_log_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(routing_logs_dir(app)?.join("xray-runtime.log"))
}

fn append_runtime_event(app: &AppHandle, line: &str) -> Result<(), String> {
    let log_path = routing_event_log_path(app)?;
    append_log_line(&log_path, "ROUTING", line)
}

fn tail_runtime_log(app: &AppHandle, lines: usize) -> Result<Vec<String>, String> {
    let log_path = runtime_log_path(app)?;
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&log_path)
        .map_err(|error| format!("Не удалось прочитать лог runtime: {error}"))?;

    let collected = content
        .lines()
        .rev()
        .take(lines)
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    Ok(collected)
}

fn strip_windows_exe_suffix(value: &str) -> String {
    if value.len() > 4 && value.to_ascii_lowercase().ends_with(".exe") {
        value[..value.len() - 4].to_string()
    } else {
        value.to_string()
    }
}

fn normalize_process_match(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed.replace('\\', "/");
    if normalized.contains('/') {
        Some(normalized)
    } else {
        Some(strip_windows_exe_suffix(&normalized))
    }
}

#[cfg(target_os = "windows")]
fn resolve_service_process_match(service_value: &str) -> Result<Option<(String, String)>, String> {
    let service_name = service_value.trim();
    if service_name.is_empty() {
        return Ok(None);
    }

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$name = '{}'
$service = Get-CimInstance Win32_Service | Where-Object {{ $_.Name -ieq $name -or $_.DisplayName -ieq $name }} | Select-Object -First 1 Name, DisplayName, PathName
if (-not $service) {{
  ''
  exit 0
}}
$raw = [Environment]::ExpandEnvironmentVariables([string]$service.PathName)
$exe = $null
if ($raw -match '^\s*"([^"]+?\.exe)"') {{
  $exe = $Matches[1]
}} elseif ($raw -match '^\s*([^ ]+?\.exe)\b') {{
  $exe = $Matches[1]
}} elseif ($raw -match '([A-Za-z]:\\[^\"]+?\.exe)') {{
  $exe = $Matches[1]
}}
if (-not $exe) {{
  $exe = $raw
}}
$exe = $exe.Replace('\\', '/')
$fileName = [System.IO.Path]::GetFileName($exe)
[pscustomobject]@{{
  name = $service.Name
  displayName = $service.DisplayName
  exePath = $exe
  isSharedHost = ($fileName -ieq 'svchost.exe') -or ($fileName -ieq 'services.exe')
}} | ConvertTo-Json -Compress
"#,
        ps_quote(service_name)
    );

    let raw = run_powershell(&script)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let payload = serde_json::from_str::<ServiceLookupInfo>(trimmed)
        .map_err(|error| format!("Не удалось разобрать описание службы {}: {error}", service_name))?;

    if payload.is_shared_host {
        return Ok(None);
    }

    let normalized = normalize_process_match(&payload.exe_path);
    Ok(normalized.map(|value| {
        (
            value,
            format!("{} ({})", payload.name, payload.display_name),
        )
    }))
}

#[cfg(not(target_os = "windows"))]
fn resolve_service_process_match(_service_value: &str) -> Result<Option<(String, String)>, String> {
    Ok(None)
}

fn build_split_tunnel_rule_plan(entries: &[SplitTunnelEntryPayload]) -> SplitTunnelRulePlan {
    let mut process_matches = Vec::new();
    let mut resolved_apps = 0usize;
    let mut resolved_services = 0usize;
    let mut skipped_notes = Vec::new();

    for entry in entries.iter().filter(|item| item.enabled) {
        let raw_value = entry.value.trim();
        if raw_value.is_empty() {
            continue;
        }

        match entry.kind.to_ascii_lowercase().as_str() {
            "service" => match resolve_service_process_match(raw_value) {
                Ok(Some((resolved, _label))) => {
                    if !process_matches.contains(&resolved) {
                        process_matches.push(resolved);
                        resolved_services += 1;
                    }
                }
                Ok(None) => skipped_notes.push(format!(
                    "Служба {} пропущена: Xray может точно разделять только службы с собственным exe-файлом, а не общие svchost/services процессы.",
                    raw_value
                )),
                Err(error) => skipped_notes.push(error),
            },
            _ => {
                if let Some(normalized) = normalize_process_match(raw_value) {
                    if !process_matches.contains(&normalized) {
                        process_matches.push(normalized);
                        resolved_apps += 1;
                    }
                }
            }
        }
    }

    SplitTunnelRulePlan {
        process_matches,
        resolved_apps,
        resolved_services,
        skipped_notes,
    }
}

fn private_bypass_cidrs() -> Vec<&'static str> {
    vec![
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
}

fn build_xray_config(
    template: &RuntimeTemplate,
    network_mode: &str,
    send_through_ip: Option<&str>,
    split_tunnel_entries: &[SplitTunnelEntryPayload],
    runtime_log_path: Option<&Path>,
) -> (Value, SplitTunnelRulePlan) {
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

    let mut outbound = if template.outbound.is_object() {
        template.outbound.clone()
    } else {
        json!({})
    };

    if let Some(map) = outbound.as_object_mut() {
        map.insert("tag".to_string(), Value::String("proxy".to_string()));
        if let Some(ip) = send_through_ip {
            map.entry("sendThrough".to_string())
                .or_insert_with(|| Value::String(ip.to_string()));
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
                "destOverride": ["http", "tls", "quic"]
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
                "destOverride": ["http", "tls"]
            }
        }),
    ];

    let mut routing_rules = Vec::new();

    if network_mode == "tun" {
        inbounds.push(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": TUN_INTERFACE_NAME,
                "MTU": 1500,
                "userLevel": 0
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
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
            "loglevel": "debug",
            "error": path.to_string_lossy().to_string(),
            "access": ""
        })
    } else {
        json!({
            "loglevel": "warning"
        })
    };

    (
        json!({
            "log": log_object,
            "dns": {
                "servers": ["1.1.1.1", "8.8.8.8", "localhost"]
            },
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
    )
}

fn extract_outbound_address_and_port(template: &RuntimeTemplate) -> (Option<String>, u16) {
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
            .and_then(|value| value.as_u64())
            .map(|value| value as u16)
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
            .and_then(|value| value.as_u64())
            .map(|value| value as u16)
            .unwrap_or(default_port);
        return (address, port);
    }

    (None, default_port)
}

fn resolve_ipv4_address(host: &str, port: u16) -> Option<String> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|items| items.into_iter().find(|addr| addr.ip().is_ipv4()))
        .map(|addr| addr.ip().to_string())
}

fn detect_primary_ipv4_address() -> Option<String> {
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
fn default_route_snapshot() -> Result<DefaultRouteSnapshot, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.State -eq 'Alive' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 InterfaceAlias, InterfaceIndex, NextHop
if (-not $route) { throw 'Default route not found' }
$route | ConvertTo-Json -Compress
"#;

    let raw = run_powershell(script)?;
    serde_json::from_str::<DefaultRouteSnapshot>(&raw)
        .map_err(|error| format!("Не удалось разобрать снимок default route: {error}"))
}

#[cfg(target_os = "windows")]
fn wait_for_tun_interface(interface_name: &str) -> Result<(), String> {
    for _ in 0..20 {
        let script = format!(
            r#"
$adapter = Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue
if ($adapter) {{ 'ready' }}
"#,
            ps_quote(interface_name)
        );

        if run_powershell(&script)
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("ready")
        {
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(250));
    }

    Err(format!(
        "TUN интерфейс {} не появился после запуска Xray.",
        interface_name
    ))
}

#[cfg(target_os = "windows")]
fn configure_tun_routes(interface_name: &str, server_ip: Option<&str>) -> Result<(), String> {
    wait_for_tun_interface(interface_name)?;
    let default_route = default_route_snapshot()?;

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
New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceAlias $tun -NextHop '0.0.0.0' -RouteMetric 6 -PolicyStore ActiveStore | Out-Null
New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceAlias $tun -NextHop '0.0.0.0' -RouteMetric 6 -PolicyStore ActiveStore | Out-Null
{}
"#,
        ps_quote(interface_name),
        server_route
    );

    run_powershell(&script)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn configure_tun_routes(_interface_name: &str, _server_ip: Option<&str>) -> Result<(), String> {
    Err("TUN маршруты сейчас реализованы только для Windows сборки VKarmani.".into())
}

#[cfg(target_os = "windows")]
fn cleanup_tun_routes(interface_name: &str, server_ip: Option<&str>) -> Result<(), String> {
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
fn cleanup_tun_routes(_interface_name: &str, _server_ip: Option<&str>) -> Result<(), String> {
    Ok(())
}


fn stop_existing_runtime(app: &AppHandle, state: &tauri::State<AppState>) -> Result<(), String> {
    let mut runtime_guard = state
        .runtime
        .lock()
        .map_err(|_| "Не удалось получить доступ к runtime состоянию.".to_string())?;

    if let Some(mut runtime) = runtime_guard.take() {
        let _ = append_runtime_event(app, "Останавливаем предыдущий Xray runtime.");
        let _ = runtime.child.kill();
        let status = runtime.child.wait().ok();

        if runtime.network_mode == "tun" {
            let _ = cleanup_tun_routes(
                runtime.tun_interface_name.as_deref().unwrap_or(TUN_INTERFACE_NAME),
                runtime.tun_server_ip.as_deref(),
            );
        }

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

    Ok(())
}

fn tcp_port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);

    addr.to_socket_addrs()
        .ok()
        .and_then(|mut values| values.next())
        .map(|socket| TcpStream::connect_timeout(&socket, timeout).is_ok())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<String, String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|error| format!("Не удалось запустить PowerShell: {error}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(target_os = "windows")]
fn current_proxy_snapshot() -> Result<ProxyStatus, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$value = Get-ItemProperty -Path $key
[pscustomobject]@{
  enabled = [bool]($value.ProxyEnable -eq 1)
  server = [string]$value.ProxyServer
  bypass = [string]$value.ProxyOverride
} | ConvertTo-Json -Compress
"#;

    let raw = run_powershell(script)?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Не удалось разобрать ответ PowerShell: {error}"))?;

    Ok(ProxyStatus {
        enabled: value.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        server: value
            .get("server")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        bypass: value
            .get("bypass")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        method: "wininet-registry".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}

#[cfg(not(target_os = "windows"))]
fn current_proxy_snapshot() -> Result<ProxyStatus, String> {
    Ok(ProxyStatus {
        enabled: false,
        server: None,
        bypass: None,
        method: "mock".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}

#[cfg(target_os = "windows")]
fn set_windows_proxy(enabled: bool) -> Result<ProxyStatus, String> {
    let proxy_enable = if enabled { 1 } else { 0 };
    let proxy_server = if enabled {
        format!("http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT}")
    } else {
        String::new()
    };

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty -Path $key -Name ProxyEnable -Value {proxy_enable}
Set-ItemProperty -Path $key -Name ProxyServer -Value '{proxy_server}'
Set-ItemProperty -Path $key -Name ProxyOverride -Value '{proxy_bypass}'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WinInetNative {{
  [DllImport("wininet.dll", SetLastError=true)]
  public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}}
"@
[WinInetNative]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInetNative]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
"#,
        proxy_enable = proxy_enable,
        proxy_server = proxy_server,
        proxy_bypass = PROXY_BYPASS,
    );

    run_powershell(&script)?;
    current_proxy_snapshot()
}

#[cfg(not(target_os = "windows"))]
fn set_windows_proxy(enabled: bool) -> Result<ProxyStatus, String> {
    Ok(ProxyStatus {
        enabled,
        server: if enabled {
            Some(format!("http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT}"))
        } else {
            None
        },
        bypass: if enabled {
            Some(PROXY_BYPASS.to_string())
        } else {
            None
        },
        method: "mock".into(),
        scope: "current-user".into(),
        checked_at: unix_now_string(),
    })
}


#[cfg(target_os = "windows")]
fn is_process_elevated() -> Result<bool, String> {
    let script = r#"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'true' } else { 'false' }
"#;

    let raw = run_powershell(script)?;
    Ok(raw.trim().eq_ignore_ascii_case("true"))
}

#[cfg(not(target_os = "windows"))]
fn is_process_elevated() -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "windows")]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn sync_runtime_liveness(app: &AppHandle, state: &tauri::State<AppState>) {
    let mut exit_code: Option<Option<i32>> = None;

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        if let Some(runtime) = runtime_guard.as_mut() {
            match runtime.child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = Some(status.code());
                    let finished_runtime = runtime_guard.take();
                    if let Some(runtime) = finished_runtime {
                        if runtime.network_mode == "tun" {
                            let _ = cleanup_tun_routes(
                                runtime.tun_interface_name.as_deref().unwrap_or(TUN_INTERFACE_NAME),
                                runtime.tun_server_ip.as_deref(),
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = append_runtime_event(
                        app,
                        &format!("Не удалось проверить состояние Xray-core: {error}"),
                    );
                }
            }
        }
    }

    if let Some(code) = exit_code {
        if let Ok(mut exit_guard) = state.last_exit_code.lock() {
            *exit_guard = code;
        }

        if let Ok(mut guard) = state.connected.lock() {
            *guard = false;
        }

        if let Ok(mut guard) = state.active_server_label.lock() {
            *guard = None;
        }

        let _ = append_runtime_event(
            app,
            &format!("Xray-core завершился во время работы. Exit code: {:?}", code),
        );
        let _ = app.emit("vkarmani://native-disconnect", "stopped");
    }
}

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
        "Xray-core не найден. Положите xray.exe в resources/core/windows или задайте VKARMANI_XRAY_PATH.".to_string()
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
        config_path: runtime_snapshot.as_ref().map(|snapshot| snapshot.1.clone()),
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



#[tauri::command]
fn fetch_remote_text(url: String, accept: Option<String>) -> Result<String, String> {
    let client = build_http_client(None, Duration::from_secs(8))?;

    let response = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, APP_USER_AGENT)
        .header(
            reqwest::header::ACCEPT,
            accept.unwrap_or_else(|| "text/plain, application/json, text/html".to_string()),
        )
        .send()
        .map_err(|error| format!("Не удалось получить ответ от {url}: {error}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    response
        .text()
        .map_err(|error| format!("Не удалось прочитать тело ответа: {error}"))
}

#[tauri::command]
fn write_interface_log(message: String, details: Option<String>, app: AppHandle) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_interface_event(&app, &line)
}

#[tauri::command]
fn write_routing_log(message: String, details: Option<String>, app: AppHandle) -> Result<(), String> {
    let line = details
        .filter(|value| !value.trim().is_empty())
        .map(|details| format!("{message} | {details}"))
        .unwrap_or(message);
    append_runtime_event(&app, &line)
}

#[tauri::command]
fn public_ip_snapshot(mode: Option<String>) -> Result<String, String> {
    let normalized_mode = mode.unwrap_or_else(|| "direct".to_string()).to_lowercase();

    if normalized_mode == "runtime" {
        if !tcp_port_open("127.0.0.1", HTTP_PORT, 1200) {
            return Err(format!("HTTP inbound 127.0.0.1:{HTTP_PORT} не отвечает. Сначала запустите runtime."));
        }

        let client = build_http_client(Some(&format!("http://127.0.0.1:{HTTP_PORT}")), Duration::from_secs(8))?;
        return fetch_public_ip(&client);
    }

    let client = build_http_client(None, Duration::from_secs(4))?;
    fetch_public_ip(&client)
}

#[tauri::command]
fn bootstrap_info() -> BootstrapInfo {
    BootstrapInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
    }
}

#[tauri::command]
fn runtime_status(app: AppHandle, state: tauri::State<AppState>) -> RuntimeStatus {
    build_runtime_status(&app, state)
}

#[tauri::command]
fn request_connect(
    server_id: String,
    server_label: String,
    runtime_template: RuntimeTemplate,
    network_mode: Option<String>,
    split_tunnel_entries: Option<Vec<SplitTunnelEntryPayload>>,
    state: tauri::State<AppState>,
    app: AppHandle,
) -> Result<RuntimeStatus, String> {
    if runtime_template.family.to_lowercase() != "xray" {
        return Err("Сейчас поддерживается только Xray runtime family.".into());
    }

    let core_path = resolve_core_path(&app)
        .ok_or_else(|| "Xray-core не найден. Положите xray.exe в resources/core/windows или задайте VKARMANI_XRAY_PATH.".to_string())?;

    let normalized_network_mode = match network_mode
        .unwrap_or_else(|| "proxy".to_string())
        .to_lowercase()
        .as_str()
    {
        "tun" => "tun".to_string(),
        _ => "proxy".to_string(),
    };

    let (outbound_host, outbound_port) = extract_outbound_address_and_port(&runtime_template);
    let outbound_ip = outbound_host
        .as_deref()
        .and_then(|host| resolve_ipv4_address(host, outbound_port));
    let send_through_ip = if normalized_network_mode == "tun" {
        detect_primary_ipv4_address()
    } else {
        None
    };

    #[cfg(target_os = "windows")]
    if normalized_network_mode == "tun" && !is_process_elevated()? {
        return Err("TUN режим требует запуска VKarmani с правами администратора, иначе Windows не даст создать маршруты. Откройте настройки клиента и включите запуск от администратора или перезапустите приложение вручную от имени администратора.".into());
    }

    if normalized_network_mode == "tun" && send_through_ip.is_none() {
        return Err("Не удалось определить локальный IPv4 адрес активного сетевого адаптера для TUN режима. Подключитесь к сети без VPN/виртуального адаптера и попробуйте снова.".into());
    }

    stop_existing_runtime(&app, &state)?;

    let output_dir = runtime_output_dir(&app)?;
    let config_path = output_dir.join("xray-config.json");
    let active_split_tunnel_entries = split_tunnel_entries.unwrap_or_default();
    let runtime_trace_path = runtime_log_path(&app)?;
    let _ = fs::write(&runtime_trace_path, "");
    let log_path = runtime_trace_path.clone();

    let (config, split_tunnel_plan) = build_xray_config(
        &runtime_template,
        &normalized_network_mode,
        send_through_ip.as_deref(),
        &active_split_tunnel_entries,
        Some(runtime_trace_path.as_path()),
    );
    let config_text = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Не удалось сериализовать config: {error}"))?;
    fs::write(&config_path, config_text).map_err(|error| format!("Не удалось записать config: {error}"))?;

    if normalized_network_mode == "tun" {
        let core_dir = core_path.parent().map(|value| value.to_path_buf());
        let geoip_exists = core_dir
            .as_ref()
            .map(|dir| dir.join("geoip.dat").exists())
            .unwrap_or(false);
        let geosite_exists = core_dir
            .as_ref()
            .map(|dir| dir.join("geosite.dat").exists())
            .unwrap_or(false);
        let wintun_exists = core_dir
            .as_ref()
            .map(|dir| dir.join("wintun.dll").exists())
            .unwrap_or(false);
        let _ = append_runtime_event(
            &app,
            &format!(
                "TUN diagnostics: core={} | config={} | runtimeLog={} | geoip.dat={} | geosite.dat={} | wintun.dll={} | outboundHost={} | outboundIp={} | sendThrough={}",
                core_path.display(),
                config_path.display(),
                log_path.display(),
                geoip_exists,
                geosite_exists,
                wintun_exists,
                outbound_host.as_deref().unwrap_or("—"),
                outbound_ip.as_deref().unwrap_or("—"),
                send_through_ip.as_deref().unwrap_or("—")
            ),
        );

        if !wintun_exists {
            return Err(format!(
                "TUN режим не может стартовать: рядом с xray.exe отсутствует wintun.dll. Положите официальный amd64 wintun.dll в {} и повторите подключение.",
                core_dir
                    .as_ref()
                    .map(|dir| dir.display().to_string())
                    .unwrap_or_else(|| "resources/core/windows".to_string())
            ));
        }
    }

    append_runtime_event(
        &app,
        &format!(
            "Запуск Xray runtime для {server_label} · mode={} · protocol={} · remarks={}",
            normalized_network_mode,
            runtime_template.protocol,
            runtime_template.remarks.unwrap_or_else(|| "—".into())
        ),
    )?;

    if normalized_network_mode == "tun" {
        if split_tunnel_plan.process_matches.is_empty() {
            let _ = append_runtime_event(
                &app,
                "TUN selective mode: список программ пуст, поэтому невыбранный трафик будет обходить VPN напрямую.",
            );
        } else {
            let _ = append_runtime_event(
                &app,
                &format!(
                    "TUN selective mode: {} app rule(s), {} service rule(s), total process matches {}.",
                    split_tunnel_plan.resolved_apps,
                    split_tunnel_plan.resolved_services,
                    split_tunnel_plan.process_matches.len()
                ),
            );
        }

        for note in &split_tunnel_plan.skipped_notes {
            let _ = append_runtime_event(&app, note);
        }
    }

    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("Не удалось открыть stdout log: {error}"))?;
    let stderr_file = stdout_file
        .try_clone()
        .map_err(|error| format!("Не удалось дублировать stderr log: {error}"))?;

    let core_working_dir = core_path.parent().ok_or_else(|| {
        "Не удалось определить рабочую папку Xray-core для запуска runtime.".to_string()
    })?;

    let mut child = Command::new(&core_path)
        .current_dir(core_working_dir)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|error| format!("Не удалось запустить Xray-core: {error}"))?;

    std::thread::sleep(Duration::from_millis(350));
    if let Some(status) = child
        .try_wait()
        .map_err(|error| format!("Не удалось проверить статус Xray-core: {error}"))?
    {
        let code = status.code();
        if let Ok(mut exit_guard) = state.last_exit_code.lock() {
            *exit_guard = code;
        }
        let log_excerpt = read_runtime_log_excerpt(&log_path, 8);
        let joined_excerpt = log_excerpt.join(" | ");
        let _ = append_runtime_event(
            &app,
            &format!("Xray-core завершился сразу после старта. Exit code: {:?}", code),
        );

        if joined_excerpt.to_ascii_lowercase().contains("wintun.dll") {
            return Err(format!(
                "Xray-core не смог запустить TUN: отсутствует или не загружается wintun.dll рядом с xray.exe. Проверьте {}.",
                core_working_dir.display()
            ));
        }

        if !joined_excerpt.is_empty() {
            return Err(format!(
                "Xray-core завершился сразу после запуска. Exit code: {:?}. Последние строки xray-runtime.log: {}",
                code,
                joined_excerpt
            ));
        }

        return Err(format!(
            "Xray-core завершился сразу после запуска. Exit code: {:?}. Проверьте xray-runtime.log.",
            code
        ));
    }

    if normalized_network_mode == "tun" {
        configure_tun_routes(TUN_INTERFACE_NAME, outbound_ip.as_deref()).map_err(|error| {
            let _ = child.kill();
            let _ = child.wait();
            format!("Не удалось подготовить Windows-маршруты для TUN режима: {error}")
        })?;
        let _ = append_runtime_event(&app, "TUN маршруты применены для текущего сеанса.");
    }

    if let Ok(mut guard) = state.connected.lock() {
        *guard = true;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = Some(server_label.clone());
    }

    if let Ok(mut exit_guard) = state.last_exit_code.lock() {
        *exit_guard = None;
    }

    if let Ok(mut runtime_guard) = state.runtime.lock() {
        *runtime_guard = Some(ManagedCore {
            child,
            core_path: core_path.to_string_lossy().to_string(),
            config_path: config_path.to_string_lossy().to_string(),
            log_path: log_path.to_string_lossy().to_string(),
            server_id: server_id.clone(),
            started_at: unix_now_string(),
            network_mode: normalized_network_mode.clone(),
            tun_interface_name: if normalized_network_mode == "tun" {
                Some(TUN_INTERFACE_NAME.to_string())
            } else {
                None
            },
            tun_server_ip: if normalized_network_mode == "tun" {
                outbound_ip.clone()
            } else {
                None
            },
        });
    }

    let _ = app.emit("vkarmani://native-connect", server_id);
    let _ = app.emit("vkarmani://native-status", server_label);

    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
fn request_disconnect(state: tauri::State<AppState>, app: AppHandle) -> Result<RuntimeStatus, String> {
    stop_existing_runtime(&app, &state)?;

    if let Ok(mut guard) = state.connected.lock() {
        *guard = false;
    }

    if let Ok(mut guard) = state.active_server_label.lock() {
        *guard = None;
    }

    let _ = append_runtime_event(&app, "Xray runtime остановлен пользователем.");
    let _ = app.emit("vkarmani://native-disconnect", "idle");
    Ok(build_runtime_status(&app, state))
}

#[tauri::command]
fn cache_profile_sync(profile_count: usize, source: String, state: tauri::State<AppState>, app: AppHandle) {
    if let Ok(mut guard) = state.profile_count.lock() {
        *guard = profile_count;
    }

    if let Ok(mut guard) = state.last_sync_source.lock() {
        *guard = Some(source.clone());
    }

    let _ = append_interface_event(
        &app,
        &format!("Кэш профиля обновлён. Профилей: {profile_count} | источник: {source}"),
    );
}

#[tauri::command]
fn request_show(app: AppHandle) {
    let _ = append_interface_event(&app, "Окно приложения раскрыто пользователем.");
    reveal_main_window(&app);
}

#[tauri::command]
fn window_minimize(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно свёрнуто.");
    window.minimize().map_err(|error| format!("Не удалось свернуть окно: {error}"))
}

#[tauri::command]
fn window_toggle_maximize(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let is_maximized = window
        .is_maximized()
        .map_err(|error| format!("Не удалось прочитать состояние окна: {error}"))?;

    if is_maximized {
        let _ = append_interface_event(&app, "Главное окно восстановлено из максимального режима.");
        window
            .unmaximize()
            .map_err(|error| format!("Не удалось восстановить окно: {error}"))
    } else {
        let _ = append_interface_event(&app, "Главное окно развернуто на весь экран.");
        window
            .maximize()
            .map_err(|error| format!("Не удалось развернуть окно: {error}"))
    }
}

#[tauri::command]
fn window_close(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно закрыто.");
    window.close().map_err(|error| format!("Не удалось закрыть окно: {error}"))
}

#[tauri::command]
fn window_hide(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    let _ = append_interface_event(&app, "Главное окно скрыто в трей.");
    window.hide().map_err(|error| format!("Не удалось скрыть окно: {error}"))
}

#[tauri::command]
fn window_start_drag(window: tauri::WebviewWindow) -> Result<(), String> {
    window
        .start_dragging()
        .map_err(|error| format!("Не удалось начать перемещение окна: {error}"))
}


#[tauri::command]
fn ensure_admin_launch(app: AppHandle) -> Result<bool, String> {
    #[cfg(all(not(debug_assertions), target_os = "windows"))]
    {
        if is_process_elevated()? {
            return Ok(false);
        }

        let executable = std::env::current_exe()
            .map_err(|error| format!("Не удалось определить путь к приложению: {error}"))?;

        let args = std::env::args().skip(1).map(|item| ps_quote(&item)).collect::<Vec<_>>();
        let args_block = if args.is_empty() {
            String::new()
        } else {
            format!(" -ArgumentList @('{}')", args.join("','"))
        };

        let script = format!(
            "Start-Process -FilePath '{}'{} -Verb RunAs",
            ps_quote(&executable.to_string_lossy()),
            args_block
        );

        run_powershell(&script)?;
        app.exit(0);
        Ok(true)
    }

    #[cfg(not(all(not(debug_assertions), target_os = "windows")))]
    {
        let _ = app;
        Ok(false)
    }
}

#[tauri::command]
fn set_launch_on_startup(enabled: bool, app: AppHandle) -> Result<bool, String> {
    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    {
        let executable = std::env::current_exe()
            .map_err(|error| format!("Не удалось определить путь к приложению: {error}"))?;
        let executable = ps_quote(&executable.to_string_lossy());

        let script = if enabled {
            format!(
                r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $key -Force | Out-Null
$exe = '{}'
$quoted = '"' + $exe + '"'
Set-ItemProperty -Path $key -Name '{}' -Value $quoted
"#,
                executable,
                STARTUP_REGISTRY_VALUE
            )
        } else {
            format!(
                r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $key -Name '{}' -ErrorAction SilentlyContinue
"#,
                STARTUP_REGISTRY_VALUE
            )
        };

        run_powershell(&script)?;
        let _ = append_interface_event(
            &app,
            if enabled {
                "Автозапуск приложения включён для текущего пользователя."
            } else {
                "Автозапуск приложения отключён для текущего пользователя."
            },
        );
        Ok(enabled)
    }

    #[cfg(any(not(target_os = "windows"), debug_assertions))]
    {
        let _ = (enabled, app);
        Ok(false)
    }
}

#[tauri::command]
fn proxy_status() -> Result<ProxyStatus, String> {
    current_proxy_snapshot()
}

#[tauri::command]
fn set_system_proxy(enabled: bool, app: AppHandle, state: tauri::State<AppState>) -> Result<ProxyStatus, String> {
    let is_connected = state.connected.lock().map(|value| *value).unwrap_or(false);
    if enabled && !is_connected {
        return Err("Сначала запустите runtime, затем включайте системный proxy.".into());
    }

    let status = set_windows_proxy(enabled)?;
    let _ = append_runtime_event(
        &app,
        &format!(
            "Windows system proxy {} | server={} | bypass={}",
            if enabled { "включён" } else { "отключён" },
            status.server.clone().unwrap_or_else(|| "—".into()),
            status.bypass.clone().unwrap_or_else(|| "—".into())
        ),
    );
    Ok(status)
}

#[tauri::command]
fn connectivity_probe() -> Result<ConnectivityProbe, String> {
    let checked_at = unix_now_string();
    let http_port_open = tcp_port_open("127.0.0.1", HTTP_PORT, 1200);
    let socks_port_open = tcp_port_open("127.0.0.1", SOCKS_PORT, 1200);

    if !http_port_open {
        return Ok(ConnectivityProbe {
            success: false,
            checked_at,
            http_port_open,
            socks_port_open,
            public_ip: None,
            latency_ms: None,
            message: format!("HTTP inbound 127.0.0.1:{HTTP_PORT} не отвечает. Сначала запустите runtime."),
        });
    }

    let client = build_http_client(Some(&format!("http://127.0.0.1:{HTTP_PORT}")), Duration::from_secs(8))?;

    let started = Instant::now();
    let public_ip = fetch_public_ip(&client)?;

    Ok(ConnectivityProbe {
        success: true,
        checked_at,
        http_port_open,
        socks_port_open,
        public_ip: Some(public_ip),
        latency_ms: Some(started.elapsed().as_millis()),
        message: "Маршрут через локальный Xray runtime отвечает.".into(),
    })
}

#[tauri::command]
fn read_runtime_log(app: AppHandle, lines: Option<usize>) -> Result<Vec<String>, String> {
    tail_runtime_log(&app, lines.unwrap_or(20).clamp(1, 200))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            let _ = interface_logs_dir(&app.handle());
            let _ = routing_logs_dir(&app.handle());
            let _ = ensure_log_tree(&app.handle());
            let _ = append_interface_event(&app.handle(), "Приложение запущено. Структура логов проверена.");
            let _ = append_runtime_event(&app.handle(), "Routing/runtime лог инициализирован. Ожидание действий пользователя.");
            let show_item = MenuItem::with_id(app, "show", "Открыть VKarmani", true, None::<&str>)?;
            let connect_item =
                MenuItem::with_id(app, "connect", "Быстрое подключение", true, None::<&str>)?;
            let disconnect_item =
                MenuItem::with_id(app, "disconnect", "Отключиться", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&show_item, &connect_item, &disconnect_item, &quit_item])?;

            TrayIconBuilder::new()
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
                    "quit" => {
                        let _ = append_interface_event(app, "Tray: выход из приложения.");
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
            runtime_status,
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
            public_ip_snapshot,
            connectivity_probe,
            read_runtime_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running VKarmani Desktop");
}
