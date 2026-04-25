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
