use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

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

#[cfg(target_os = "windows")]
fn hide_child_console(command: &mut Command) {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_child_console(_command: &mut Command) {}


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

#[allow(dead_code)]
fn looks_like_launch_root(path: &Path) -> bool {
    path.join("package.json").exists()
        || path.join("START_VKarmani.bat").exists()
        || path.join("resources").exists()
        || path.join("src-tauri").exists()
}

#[allow(dead_code)]
fn looks_like_tauri_subdir(path: &Path) -> bool {
    matches!(path.file_name().and_then(|name| name.to_str()), Some("src-tauri") | Some("target") | Some("debug") | Some("release"))
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn push_candidate_dir(candidates: &mut Vec<PathBuf>, value: Option<PathBuf>) {
    if let Some(path) = value {
        let normalized = normalize_log_base_candidate(path);
        if !candidates.iter().any(|item| item == &normalized) {
            candidates.push(normalized);
        }
    }
}

fn app_logs_base_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения для логов: {error}"))?;
    let logs_root = base.join("logs");
    fs::create_dir_all(&logs_root)
        .map_err(|error| format!("Не удалось создать logs каталог в app data: {error}"))?;
    Ok(logs_root)
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

fn redact_sensitive(input: &str) -> String {
    let mut result = input.to_string();
    for scheme in ["vless://", "vmess://", "trojan://", "ss://"] {
        while let Some(start) = result.to_ascii_lowercase().find(scheme) {
            let end = result[start..]
                .find(char::is_whitespace)
                .map(|offset| start + offset)
                .unwrap_or(result.len());
            result.replace_range(start..end, "[redacted-vpn-link]");
        }
    }

    let mut output = String::with_capacity(result.len());
    for token in result.split_whitespace() {
        let trimmed = token.trim_matches(|c: char| {
            !c.is_ascii_alphanumeric()
                && c != '-'
                && c != '_'
                && c != '='
                && c != ':'
                && c != '/'
                && c != '.'
                && c != '?'
                && c != '&'
        });
        let should_mask = trimmed.len() >= 28
            && trimmed.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 20
            && (trimmed.contains('-') || trimmed.contains('_') || trimmed.contains('=') || trimmed.contains("http"));

        let rendered = if should_mask {
            let prefix: String = trimmed.chars().take(6).collect();
            let suffix_rev: String = trimmed.chars().rev().take(4).collect();
            let suffix: String = suffix_rev.chars().rev().collect();
            token.replace(trimmed, &format!("{prefix}…{suffix}"))
        } else {
            token.to_string()
        };

        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str(&rendered);
    }

    output
}

fn append_log_line(path: &PathBuf, scope: &str, line: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("Не удалось открыть лог-файл {}: {error}", path.display()))?;

    writeln!(file, "[{}] [{}] {}", log_timestamp_string(), scope, redact_sensitive(line))
        .map_err(|error| format!("Не удалось записать лог {}: {error}", path.display()))
}

fn append_interface_event(app: &AppHandle, line: &str) -> Result<(), String> {
    let log_path = interface_log_path(app)?;
    append_log_line(&log_path, "INTERFACE", line)
}

const MIN_XRAY_CORE_SIZE_BYTES: u64 = 1_000_000;
const PE_MACHINE_AMD64: u16 = 0x8664;
const PE32_PLUS_MAGIC: u16 = 0x20b;

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|item| item == &path) {
        paths.push(path);
    }
}

fn validate_pe_binary(path: &Path, label: &str) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("не удалось открыть {label}: {error}"))?;
    let mut header = [0u8; 4096];
    let read = file
        .read(&mut header)
        .map_err(|error| format!("не удалось прочитать PE-заголовок {label}: {error}"))?;

    if read < 256 {
        return Err(format!("повреждённый PE-файл: слишком короткий заголовок, прочитано {read} байт"));
    }

    if &header[0..2] != b"MZ" {
        if &header[0..4] == [0, 0, 0, 0] && &header[4..6] == b"MZ" {
            return Err("повреждённый PE-файл: перед сигнатурой MZ есть 4 лишних нулевых байта".to_string());
        }
        if header.starts_with(b"version https://git-lfs") {
            return Err("вместо настоящего xray.exe упакован Git LFS pointer; включите checkout lfs:true в GitHub Actions и пересоберите релиз".to_string());
        }
        return Err(format!(
            "повреждённый PE-файл: ожидалась сигнатура MZ, первые байты {:02X} {:02X}",
            header[0], header[1]
        ));
    }

    let pe_offset = u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as usize;
    if !(64..=8192).contains(&pe_offset) {
        return Err(format!("повреждённый PE-файл: некорректный offset PE-заголовка {pe_offset}"));
    }
    if pe_offset + 26 > read {
        return Err(format!("повреждённый PE-файл: PE-заголовок обрывается на offset {pe_offset}"));
    }

    if &header[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(format!(
            "повреждённый PE-файл: ожидалась сигнатура PE, получено {:02X} {:02X} {:02X} {:02X}",
            header[pe_offset], header[pe_offset + 1], header[pe_offset + 2], header[pe_offset + 3]
        ));
    }

    let machine = u16::from_le_bytes([header[pe_offset + 4], header[pe_offset + 5]]);
    if machine != PE_MACHINE_AMD64 {
        return Err(format!(
            "неподходящий PE-файл: {label} должен быть Windows x64/AMD64, machine=0x{machine:04X}"
        ));
    }

    let optional_header_magic = u16::from_le_bytes([header[pe_offset + 24], header[pe_offset + 25]]);
    if optional_header_magic != PE32_PLUS_MAGIC {
        return Err(format!(
            "неподходящий PE-файл: {label} должен быть PE32+ x64, optional_header=0x{optional_header_magic:04X}"
        ));
    }

    Ok(())
}

fn format_xray_spawn_error(error: &std::io::Error, core_path: &Path) -> String {
    let code = error.raw_os_error();
    let hint = match code {
        Some(193) => "Windows вернул os error 193: установленный xray.exe не запускается как Windows x64-приложение. Обычно это значит, что в installer/updater попал неправильный или повреждённый файл xray.exe. Полностью удалите старую установку VKarmani, установите актуальную версию и убедитесь, что GitHub Actions прошёл шаг Verify bundled Xray binary on Windows.",
        Some(1392) => "Windows вернул os error 1392: файл xray.exe повреждён на диске или был частично перезаписан во время обновления. Закройте VKarmani, удалите папку core рядом с приложением и установите актуальную версию заново.",
        Some(5) => "Windows вернул os error 5: доступ запрещён. Проверьте антивирус/SmartScreen и права доступа к папке установки.",
        _ => "Проверьте, что рядом с приложением лежит настоящий Xray-core для Windows x64, а не Linux/ARM/LFS-pointer/повреждённый файл.",
    };

    format!(
        "Не удалось запустить Xray-core: {error}. Путь: {}. {hint}",
        core_path.display()
    )
}

#[cfg(target_os = "windows")]
fn ensure_core_launchable(path: &Path) -> Result<(), String> {
    validate_core_path(path)?;
    let core_working_dir = path.parent().ok_or_else(|| {
        "Не удалось определить рабочую папку Xray-core для проверки запуска.".to_string()
    })?;

    let mut command = Command::new(path);
    command
        .current_dir(core_working_dir)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hide_child_console(&mut command);

    let status = command
        .status()
        .map_err(|error| format_xray_spawn_error(&error, path))?;

    if !status.success() {
        return Err(format!(
            "Xray-core найден, но проверка xray.exe version завершилась с кодом {:?}. Путь: {}",
            status.code(),
            path.display()
        ));
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn ensure_core_launchable(path: &Path) -> Result<(), String> {
    validate_core_path(path)
}

fn validate_core_path(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("не удалось проверить файл: {error}"))?;
    if !metadata.is_file() {
        return Err("это не файл".to_string());
    }
    if metadata.len() < MIN_XRAY_CORE_SIZE_BYTES {
        return Err(format!("слишком маленький файл: {} байт", metadata.len()));
    }
    validate_pe_binary(path, "xray.exe")
}

fn is_usable_core_path(path: &Path) -> bool {
    validate_core_path(path).is_ok()
}

fn candidate_core_paths(app: &AppHandle) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_path) = std::env::var("VKARMANI_XRAY_PATH") {
        push_unique_path(&mut paths, PathBuf::from(env_path));
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        // New fixed bundle mapping: tauri.conf.json maps resources directly to $RESOURCE/core/windows.
        push_unique_path(&mut paths, resource_dir.join("core").join("windows").join("xray.exe"));

        // Backward compatibility for older builds that used "../resources/..." in list mode.
        // Tauri stores ".." segments under "_up_", so users updating from a broken build can still be recovered.
        push_unique_path(
            &mut paths,
            resource_dir
                .join("_up_")
                .join("resources")
                .join("core")
                .join("windows")
                .join("xray.exe"),
        );

        // Extra defensive fallback for manually copied portable builds.
        push_unique_path(
            &mut paths,
            resource_dir
                .join("resources")
                .join("core")
                .join("windows")
                .join("xray.exe"),
        );
    }

    if let Ok(app_local) = app.path().app_local_data_dir() {
        push_unique_path(&mut paths, app_local.join("core").join("xray.exe"));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        push_unique_path(
            &mut paths,
            current_dir
                .join("resources")
                .join("core")
                .join("windows")
                .join("xray.exe"),
        );
        push_unique_path(&mut paths, current_dir.join("src-tauri").join("bin").join("xray.exe"));
    }

    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            push_unique_path(
                &mut paths,
                parent
                    .join("resources")
                    .join("core")
                    .join("windows")
                    .join("xray.exe"),
            );
            push_unique_path(&mut paths, parent.join("core").join("windows").join("xray.exe"));
        }
    }

    paths
}

fn resolve_core_path(app: &AppHandle) -> Option<PathBuf> {
    candidate_core_paths(app)
        .into_iter()
        .find(|path| is_usable_core_path(path))
}

fn core_not_found_message(app: &AppHandle) -> String {
    let candidates = candidate_core_paths(app)
        .into_iter()
        .map(|path| {
            let state = if path.exists() {
                match validate_core_path(&path) {
                    Ok(()) => "ok".to_string(),
                    Err(error) => error,
                }
            } else {
                "нет файла".to_string()
            };

            format!("{} ({state})", path.display())
        })
        .collect::<Vec<_>>()
        .join("; ");

    if candidates.is_empty() {
        "Xray-core не найден. В сборке должен быть файл core/windows/xray.exe, либо задайте VKARMANI_XRAY_PATH.".to_string()
    } else {
        format!(
            "Xray-core не найден или повреждён. В сборке должен быть файл core/windows/xray.exe, либо задайте VKARMANI_XRAY_PATH. Проверенные пути: {candidates}"
        )
    }
}

#[allow(dead_code)]
fn resolve_core_sidecar_path(core_path: &Path, file_name: &str) -> Option<PathBuf> {
    core_path.parent().map(|dir| dir.join(file_name))
}

#[tauri::command]
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

fn cleanup_runtime_config_files(app: &AppHandle) -> Result<(), String> {
    let dir = runtime_output_dir(app)?;
    for entry in fs::read_dir(&dir).map_err(|error| format!("Не удалось прочитать runtime каталог: {error}"))? {
        let path = entry.map_err(|error| format!("Не удалось прочитать runtime файл: {error}"))?.path();
        let name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
        if name.starts_with("xray-config") && name.ends_with(".json") {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
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

                let _ = fs::remove_file(Path::new(&runtime.config_path));

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
    let mut command = Command::new("powershell");
    hide_child_console(&mut command);
    let output = command
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
fn run_powershell_with_env(script: &str, envs: &[(String, String)]) -> Result<String, String> {
    let mut command = Command::new("powershell");
    hide_child_console(&mut command);
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
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
fn apply_windows_proxy_snapshot(snapshot: &ProxyStatus) -> Result<ProxyStatus, String> {
    let proxy_enable = if snapshot.enabled { 1 } else { 0 };
    let proxy_server = snapshot.server.clone().unwrap_or_default();
    let proxy_bypass = snapshot.bypass.clone().unwrap_or_default();
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
        proxy_server = ps_quote(&proxy_server),
        proxy_bypass = ps_quote(&proxy_bypass),
    );
    run_powershell(&script)?;
    current_proxy_snapshot()
}

#[cfg(not(target_os = "windows"))]
fn apply_windows_proxy_snapshot(snapshot: &ProxyStatus) -> Result<ProxyStatus, String> {
    Ok(ProxyStatus {
        enabled: snapshot.enabled,
        server: snapshot.server.clone(),
        bypass: snapshot.bypass.clone(),
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



fn validate_remote_fetch_url(raw_url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(raw_url).map_err(|_| "Некорректный URL для удалённого запроса.".to_string())?;
    if parsed.scheme() != "https" {
        return Err("Удалённые запросы разрешены только по HTTPS.".into());
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".local")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.2")
        || host.starts_with("172.30.")
        || host.starts_with("172.31.")
        || host == "0.0.0.0"
    {
        return Err("Локальные и приватные адреса запрещены для удалённого fetch.".into());
    }
    Ok(())
}

#[tauri::command]
fn fetch_remote_text(url: String, accept: Option<String>) -> Result<String, String> {
    validate_remote_fetch_url(&url)?;
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

fn secure_access_key_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("Не удалось определить каталог данных приложения: {error}"))?;
    fs::create_dir_all(&dir).map_err(|error| format!("Не удалось создать каталог данных приложения: {error}"))?;
    Ok(dir.join("access-key.dpapi"))
}

#[cfg(target_os = "windows")]
fn encrypt_access_key(value: &str) -> Result<String, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$plain = [Environment]::GetEnvironmentVariable('VKARMANI_ACCESS_KEY_PLAINTEXT', 'Process')
$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Convert]::ToBase64String($encrypted)
"#;
    run_powershell_with_env(script, &[("VKARMANI_ACCESS_KEY_PLAINTEXT".to_string(), value.to_string())])
}

#[cfg(target_os = "windows")]
fn decrypt_access_key(value: &str) -> Result<String, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$blob = [Environment]::GetEnvironmentVariable('VKARMANI_ACCESS_KEY_BLOB', 'Process')
$encrypted = [Convert]::FromBase64String($blob)
$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($bytes)
"#;
    run_powershell_with_env(script, &[("VKARMANI_ACCESS_KEY_BLOB".to_string(), value.to_string())])
}

#[cfg(not(target_os = "windows"))]
fn encrypt_access_key(value: &str) -> Result<String, String> {
    Ok(value.to_string())
}

#[cfg(not(target_os = "windows"))]
fn decrypt_access_key(value: &str) -> Result<String, String> {
    Ok(value.to_string())
}

#[tauri::command]
fn save_access_key_secure(value: String, app: AppHandle) -> Result<(), String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return clear_access_key_secure(app);
    }
    let encrypted = encrypt_access_key(normalized)?;
    fs::write(secure_access_key_path(&app)?, encrypted)
        .map_err(|error| format!("Не удалось сохранить ключ доступа в защищённое хранилище: {error}"))
}

#[tauri::command]
fn load_access_key_secure(app: AppHandle) -> Result<Option<String>, String> {
    let path = secure_access_key_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    let encrypted = fs::read_to_string(path)
        .map_err(|error| format!("Не удалось прочитать защищённый ключ доступа: {error}"))?;
    let value = decrypt_access_key(encrypted.trim())?;
    Ok(Some(value))
}

#[tauri::command]
fn clear_access_key_secure(app: AppHandle) -> Result<(), String> {
    let path = secure_access_key_path(&app)?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| format!("Не удалось удалить сохранённый ключ доступа: {error}"))?;
    }
    Ok(())
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
        .ok_or_else(|| core_not_found_message(&app))?;
    ensure_core_launchable(&core_path)?;

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
    let _ = cleanup_runtime_config_files(&app);
    let config_path = output_dir.join(format!("xray-config-{}-{}.json", std::process::id(), unix_now_string()));
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
        let wintun_status = core_dir
            .as_ref()
            .map(|dir| {
                let path = dir.join("wintun.dll");
                if !path.exists() {
                    "нет файла".to_string()
                } else {
                    validate_pe_binary(&path, "wintun.dll").map(|_| "ok".to_string()).unwrap_or_else(|error| error)
                }
            })
            .unwrap_or_else(|| "не удалось определить папку core".to_string());
        let wintun_exists = wintun_status == "ok";
        let _ = append_runtime_event(
            &app,
            &format!(
                "TUN diagnostics: core={} | config={} | runtimeLog={} | geoip.dat={} | geosite.dat={} | wintun.dll={} | outboundHost={} | outboundIp={} | sendThrough={}",
                core_path.display(),
                config_path.display(),
                log_path.display(),
                geoip_exists,
                geosite_exists,
                wintun_status,
                outbound_host.as_deref().unwrap_or("—"),
                outbound_ip.as_deref().unwrap_or("—"),
                send_through_ip.as_deref().unwrap_or("—")
            ),
        );

        if !wintun_exists {
            return Err(format!(
                "TUN режим не может стартовать: рядом с xray.exe отсутствует или повреждён wintun.dll ({wintun_status}). Положите официальный amd64 wintun.dll в {} и повторите подключение.",
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

    let mut command = Command::new(&core_path);
    command
        .current_dir(core_working_dir)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    hide_child_console(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format_xray_spawn_error(&error, &core_path))?;

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

    let status = if enabled {
        if let Ok(mut previous_guard) = state.previous_proxy.lock() {
            if previous_guard.is_none() {
                *previous_guard = current_proxy_snapshot().ok();
            }
        }
        set_windows_proxy(true)?
    } else {
        let previous = state.previous_proxy.lock().ok().and_then(|mut value| value.take());
        if let Some(snapshot) = previous {
            apply_windows_proxy_snapshot(&snapshot)?
        } else {
            set_windows_proxy(false)?
        }
    };

    let _ = append_runtime_event(
        &app,
        &format!(
            "Windows system proxy {} | server={} | bypass={}",
            if enabled { "включён" } else { "восстановлен/отключён" },
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

#[cfg(target_os = "windows")]
#[tauri::command]
fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-Process | Where-Object { $_.Path -and $_.Path.ToLower().EndsWith('.exe') } |
  Sort-Object ProcessName, Id |
  Select-Object -First 80 @{Name='pid';Expression={$_.Id}}, @{Name='name';Expression={ if ($_.ProcessName.ToLower().EndsWith('.exe')) { $_.ProcessName } else { $_.ProcessName + '.exe' } }}, @{Name='path';Expression={$_.Path}}, @{Name='title';Expression={$_.MainWindowTitle}} |
  ConvertTo-Json -Compress
"#;

    let raw = run_powershell(script)?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let value: Value = serde_json::from_str(&raw).map_err(|error| format!("Не удалось прочитать список процессов: {error}"))?;
    let apps: Vec<RunningAppInfo> = if value.is_array() {
        serde_json::from_value(value).map_err(|error| format!("Некорректный список процессов: {error}"))?
    } else {
        vec![serde_json::from_value(value).map_err(|error| format!("Некорректный процесс: {error}"))?]
    };

    Ok(apps
        .into_iter()
        .filter(|app| !app.name.trim().is_empty())
        .collect())
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    Ok(Vec::new())
}

#[tauri::command]
fn restart_application(app: AppHandle) -> Result<(), String> {
    let current_exe = std::env::current_exe().map_err(|error| format!("Не удалось определить путь приложения: {error}"))?;
    let mut command = Command::new(current_exe);
    hide_child_console(&mut command);
    command
        .spawn()
        .map_err(|error| format!("Не удалось перезапустить приложение: {error}"))?;
    app.exit(0);
    Ok(())
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
            let _ = cleanup_tun_routes(TUN_INTERFACE_NAME, None);
            let _ = cleanup_runtime_config_files(&app.handle());
            let _ = append_interface_event(&app.handle(), "Приложение запущено. Структура логов проверена.");
            let _ = append_runtime_event(&app.handle(), "Routing/runtime лог инициализирован. Ожидание действий пользователя.");
            let show_item = MenuItem::with_id(app, "show", "Открыть VKarmani", true, None::<&str>)?;
            let connect_item =
                MenuItem::with_id(app, "connect", "Быстрое подключение", true, None::<&str>)?;
            let disconnect_item =
                MenuItem::with_id(app, "disconnect", "Отключиться", true, None::<&str>)?;
            let restart_app_item = MenuItem::with_id(app, "restart_app", "Перезапустить программу", true, None::<&str>)?;
            let restart_proxy_item = MenuItem::with_id(app, "restart_proxy", "Перезапустить прокси", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&show_item, &connect_item, &disconnect_item, &restart_app_item, &restart_proxy_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new();
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
            save_access_key_secure,
            load_access_key_secure,
            clear_access_key_secure,
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
            read_runtime_log,
            list_running_apps,
            restart_application
        ])
        .run(tauri::generate_context!())
        .expect("error while running VKarmani Desktop");
}
