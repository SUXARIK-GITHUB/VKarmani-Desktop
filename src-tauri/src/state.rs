use super::*;

pub(crate) struct StartingCore {
    pub(crate) pid: u32,
    pub(crate) core_path: String,
    pub(crate) config_path: String,
    pub(crate) log_path: String,
    pub(crate) network_mode: String,
    pub(crate) tun_interface_name: Option<String>,
    pub(crate) tun_server_ips: Vec<String>,
    pub(crate) started_at: String,
}

pub(crate) struct ManagedCore {
    pub(crate) child: Child,
    pub(crate) core_path: String,
    pub(crate) config_path: String,
    pub(crate) log_path: String,
    pub(crate) server_id: String,
    pub(crate) server_fingerprint: Option<String>,
    pub(crate) started_at: String,
    pub(crate) network_mode: String,
    pub(crate) tun_interface_name: Option<String>,
    pub(crate) tun_server_ips: Vec<String>,
}

#[derive(Default)]
pub(crate) struct AppState {
    pub(crate) connected: Mutex<bool>,
    pub(crate) active_server_label: Mutex<Option<String>>,
    pub(crate) profile_count: Mutex<usize>,
    pub(crate) last_sync_source: Mutex<Option<String>>,
    pub(crate) runtime: Mutex<Option<ManagedCore>>,
    pub(crate) starting_runtime: Mutex<Option<StartingCore>>,
    pub(crate) last_exit_code: Mutex<Option<i32>>,
    pub(crate) previous_proxy: Mutex<Option<ProxyStatus>>,
    pub(crate) operation_lock: Mutex<()>, 
    pub(crate) session_authorized: Mutex<bool>,
    pub(crate) session_authorization: Mutex<Option<NativeSessionAuthorization>>,
    pub(crate) tray_update_available: Mutex<bool>,
    pub(crate) tray_update_busy: Mutex<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeSessionAuthorization {
    pub(crate) access_key_hash: String,
    pub(crate) expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BootstrapInfo {
    pub(crate) version: String,
    pub(crate) platform: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeStatus {
    pub(crate) bridge: String,
    pub(crate) core_installed: bool,
    pub(crate) tunnel_active: bool,
    pub(crate) active_server_label: Option<String>,
    pub(crate) profile_count: Option<usize>,
    pub(crate) last_sync_source: Option<String>,
    pub(crate) message: String,
    pub(crate) core_path: Option<String>,
    pub(crate) config_path: Option<String>,
    pub(crate) log_path: Option<String>,
    pub(crate) launch_mode: String,
    pub(crate) socks_port: Option<u16>,
    pub(crate) http_port: Option<u16>,
    pub(crate) last_prepared_server_id: Option<String>,
    pub(crate) last_prepared_server_fingerprint: Option<String>,
    pub(crate) last_prepared_at: Option<String>,
    pub(crate) last_exit_code: Option<i32>,
    pub(crate) system_proxy_enabled: Option<bool>,
    pub(crate) proxy_server: Option<String>,
    pub(crate) proxy_bypass: Option<String>,
    pub(crate) network_mode: Option<String>,
    pub(crate) tun_interface_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProxyStatus {
    pub(crate) enabled: bool,
    pub(crate) server: Option<String>,
    pub(crate) bypass: Option<String>,
    pub(crate) method: String,
    pub(crate) scope: String,
    pub(crate) checked_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunningAppInfo {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) path: Option<String>,
    pub(crate) title: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeAppInfo {
    pub(crate) app_version: String,
    pub(crate) xray_version: String,
    pub(crate) hwid: String,
    pub(crate) os_name: String,
    pub(crate) os_version: String,
    pub(crate) os_build: String,
    pub(crate) os_architecture: String,
    pub(crate) device_name: String,
    pub(crate) core_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectivityProbe {
    pub(crate) success: bool,
    pub(crate) checked_at: String,
    pub(crate) http_port_open: bool,
    pub(crate) socks_port_open: bool,
    pub(crate) public_ip: Option<String>,
    pub(crate) latency_ms: Option<u128>,
    pub(crate) packet_loss_pct: Option<u8>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrafficSnapshot {
    pub(crate) received_bytes: u64,
    pub(crate) sent_bytes: u64,
    pub(crate) checked_at: String,
    pub(crate) source: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeTemplate {
    pub(crate) family: String,
    pub(crate) protocol: String,
    pub(crate) outbound: Value,
    pub(crate) remarks: Option<String>,
    pub(crate) full_config: Option<Value>,
    pub(crate) primary_outbound_tag: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SplitTunnelEntryPayload {
    pub(crate) kind: String,
    pub(crate) value: String,
    pub(crate) enabled: bool,
}

pub(crate) struct SplitTunnelRulePlan {
    pub(crate) process_matches: Vec<String>,
    pub(crate) resolved_apps: usize,
    pub(crate) resolved_services: usize,
    pub(crate) skipped_notes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub(crate) struct RoutingExclusionSettingsPayload {
    pub(crate) enabled: bool,
    pub(crate) bypass_ru_domains: bool,
    pub(crate) bypass_su_domains: bool,
    pub(crate) bypass_rf_domains: bool,
    pub(crate) domains: Vec<String>,
    pub(crate) ips: Vec<String>,
}

pub(crate) struct RoutingExclusionRulePlan {
    pub(crate) domain_rules: Vec<String>,
    pub(crate) ip_rules: Vec<String>,
    pub(crate) skipped_notes: Vec<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceLookupInfo {
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) exe_path: String,
    pub(crate) is_shared_host: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IpifyResponse {
    pub(crate) ip: String,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct DefaultRouteSnapshot {
    pub(crate) interface_index: u32,
    pub(crate) next_hop: String,
}
