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
    previous_proxy: Mutex<Option<ProxyStatus>>,
    session_authorized: Mutex<bool>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunningAppInfo {
    pid: u32,
    name: String,
    path: Option<String>,
    title: Option<String>,
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
