use super::*;

pub(crate) fn build_http_client(
    proxy_url: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::blocking::Client, String> {
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

pub(crate) fn fetch_public_ip(client: &reqwest::blocking::Client) -> Result<String, String> {
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

pub(crate) fn reveal_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub(crate) fn unix_now_string() -> String {
    unix_timestamp_seconds().to_string()
}

pub(crate) fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

pub(crate) fn civil_date_from_unix_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

pub(crate) fn utc_date_parts() -> (i32, u32, u32, u32, u32, u32, u32) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or_default();
    let seconds = now_ms / 1000;
    let millis = (now_ms % 1000) as u32;
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days);
    let hour = (day_seconds / 3_600) as u32;
    let minute = ((day_seconds % 3_600) / 60) as u32;
    let second = (day_seconds % 60) as u32;
    (year, month, day, hour, minute, second, millis)
}

pub(crate) fn log_timestamp_string() -> String {
    let (year, month, day, hour, minute, second, millis) = utc_date_parts();
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

pub(crate) fn local_day_folder_name() -> String {
    let (year, month, day, _, _, _, _) = utc_date_parts();
    format!("{year:04}-{month:02}-{day:02}")
}

#[allow(dead_code)]
pub(crate) fn looks_like_launch_root(path: &Path) -> bool {
    path.join("package.json").exists()
        || path.join("START_VKarmani.bat").exists()
        || path.join("resources").exists()
        || path.join("src-tauri").exists()
}

#[allow(dead_code)]
pub(crate) fn looks_like_tauri_subdir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("src-tauri") | Some("target") | Some("debug") | Some("release")
    )
}

#[allow(dead_code)]
pub(crate) fn normalize_log_base_candidate(path: PathBuf) -> PathBuf {
    let mut candidate = path;

    if matches!(
        candidate.file_name().and_then(|name| name.to_str()),
        Some("src-tauri")
    ) {
        if let Some(parent) = candidate.parent() {
            candidate = parent.to_path_buf();
        }
    }

    if matches!(
        candidate.file_name().and_then(|name| name.to_str()),
        Some("debug") | Some("release")
    ) {
        if let Some(project_root) = candidate
            .parent()
            .and_then(|path| path.parent())
            .and_then(|path| path.parent())
        {
            candidate = project_root.to_path_buf();
        }
    } else if matches!(
        candidate.file_name().and_then(|name| name.to_str()),
        Some("target")
    ) {
        if let Some(project_root) = candidate.parent().and_then(|path| path.parent()) {
            candidate = project_root.to_path_buf();
        }
    }

    candidate
}

#[allow(dead_code)]
pub(crate) fn push_candidate_dir(candidates: &mut Vec<PathBuf>, value: Option<PathBuf>) {
    if let Some(path) = value {
        let normalized = normalize_log_base_candidate(path);
        if !candidates.iter().any(|item| item == &normalized) {
            candidates.push(normalized);
        }
    }
}

pub(crate) fn app_logs_base_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app.path().app_local_data_dir().map_err(|error| {
        format!("Не удалось определить каталог данных приложения для логов: {error}")
    })?;
    let logs_root = base.join("logs");
    ensure_safe_log_directory(&logs_root)
        .map_err(|error| format!("Не удалось создать logs каталог в app data: {error}"))?;
    Ok(logs_root)
}

pub(crate) fn daily_log_root(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app_logs_base_dir(app)?.join(local_day_folder_name());
    ensure_safe_log_directory(&root)
        .map_err(|error| format!("Не удалось создать каталог логов дня: {error}"))?;
    Ok(root)
}

pub(crate) fn interface_logs_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let path = daily_log_root(app)?.join("Interface");
    ensure_safe_log_directory(&path)
        .map_err(|error| format!("Не удалось создать Interface каталог: {error}"))?;
    Ok(path)
}

pub(crate) fn routing_logs_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let path = daily_log_root(app)?.join("routing");
    ensure_safe_log_directory(&path)
        .map_err(|error| format!("Не удалось создать routing каталог: {error}"))?;
    Ok(path)
}

pub(crate) fn interface_log_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(interface_logs_dir(app)?.join("interface.log"))
}

pub(crate) fn routing_event_log_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(routing_logs_dir(app)?.join("routing.log"))
}

pub(crate) fn ensure_log_file(path: &Path) -> Result<(), String> {
    validate_or_create_log(path)
}

pub(crate) fn ensure_log_tree(app: &AppHandle) -> Result<(), String> {
    let interface_path = interface_log_path(app)?;
    let routing_path = routing_event_log_path(app)?;
    let runtime_path = runtime_log_path(app)?;

    ensure_log_file(&interface_path)?;
    ensure_log_file(&routing_path)?;
    ensure_log_file(&runtime_path)?;
    Ok(())
}

pub(crate) fn redact_sensitive(input: &str) -> String {
    // Scan each token once instead of repeatedly copying/scanning the full body.
    // Remote subscriptions are bounded to 2 MiB, but may contain many links.
    let mut result = String::with_capacity(input.len());
    for token in input.split_inclusive(char::is_whitespace) {
        let lower = token.to_ascii_lowercase();
        let first = [
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
            "hy2://",
            "hysteria2://",
            "https://",
            "http://",
            "wss://",
        ]
        .iter()
        .filter_map(|scheme| lower.find(scheme).map(|start| (start, *scheme)))
        .min_by_key(|(start, _)| *start);
        if let Some((start, scheme)) = first {
            let end = token[start..]
                .find(char::is_whitespace)
                .map(|offset| start + offset)
                .unwrap_or(token.len());
            result.push_str(&token[..start]);
            result.push_str(if ["https://", "http://", "wss://"].contains(&scheme) {
                "[redacted-key]"
            } else {
                "[redacted-vpn-link]"
            });
            result.push_str(&token[end..]);
        } else {
            result.push_str(token);
        }
    }

    let mut output = String::with_capacity(result.len());
    let mut mask_remainder = false;
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
        let lower = trimmed.to_ascii_lowercase().replace(['"', '\''], "");
        let contains_secret_marker = [
            "access_key=",
            "access-key=",
            "apikey=",
            "api_key=",
            "authorization=",
            "bearer=",
            "key=",
            "password=",
            "secret=",
            "sub=",
            "subscription=",
            "token=",
            "userid:",
            "user_id:",
            "accesskey:",
            "password:",
            "token:",
            "secret:",
            "authorization:",
            "cookie:",
            "set-cookie:",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        let looks_like_uuid = trimmed.len() == 36
            && trimmed.chars().filter(|c| *c == '-').count() == 4
            && trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count() == 32;
        let header = lower == "bearer"
            || lower == "basic"
            || lower.starts_with("authorization:")
            || lower.starts_with("cookie:")
            || lower.starts_with("set-cookie:");
        let should_mask = mask_remainder
            || header
            || contains_secret_marker
            || looks_like_uuid
            || (trimmed.len() >= 28
                && trimmed
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .count()
                    >= 20
                && (trimmed.contains('-')
                    || trimmed.contains('_')
                    || trimmed.contains('=')
                    || trimmed.contains("http")));

        let rendered = if mask_remainder || header || contains_secret_marker || looks_like_uuid {
            token.replace(trimmed, "[redacted-secret]")
        } else if should_mask {
            token.replace(trimmed, "[redacted-token]")
        } else {
            token.to_string()
        };

        if header || contains_secret_marker {
            mask_remainder = true;
        }
        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str(&rendered);
    }

    output
}

pub(crate) fn append_log_line(path: &Path, scope: &str, line: &str) -> Result<(), String> {
    append_bounded_log(
        path,
        &format!(
            "[{}] [{}] {}",
            log_timestamp_string(),
            scope,
            redact_sensitive(&line.chars().take(4096).collect::<String>())
        ),
    )
}

pub(crate) fn append_interface_event(app: &AppHandle, line: &str) -> Result<(), String> {
    let log_path = interface_log_path(app)?;
    append_log_line(&log_path, "INTERFACE", line)
}

pub(crate) const MIN_XRAY_CORE_SIZE_BYTES: u64 = 1_000_000;
pub(crate) const PE_MACHINE_AMD64: u16 = 0x8664;
pub(crate) const PE32_PLUS_MAGIC: u16 = 0x20b;

pub(crate) fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|item| item == &path) {
        paths.push(path);
    }
}

pub(crate) fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

pub(crate) fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| {
        format!(
            "не удалось открыть файл для sha256 {}: {error}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            format!(
                "не удалось прочитать файл для sha256 {}: {error}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

pub(crate) fn verify_core_manifest_artifact(path: &Path, file_name: &str) -> Result<(), String> {
    // The neighboring manifest is metadata, not a mutable execution authority.
    let (expected_size, expected) = compiled_artifact_identity(file_name)?;
    if fs::metadata(path).map_err(|_| "CORE_METADATA")?.len() != expected_size {
        return Err("CORE_SIZE_MISMATCH".into());
    }
    let actual = sha256_file_hex(path)?.to_ascii_lowercase();
    if actual != expected {
        return Err(format!(
            "sha256 {file_name} не совпадает с compiled manifest pin: ожидалось {expected}, получено {actual}"
        ));
    }

    Ok(())
}

pub(crate) fn validate_core_sidecar_path(path: &Path, label: &str) -> Result<(), String> {
    validate_pe_binary(path, label)?;
    verify_core_manifest_artifact(path, label)
}

pub(crate) fn validate_pe_binary(path: &Path, label: &str) -> Result<(), String> {
    let mut file =
        File::open(path).map_err(|error| format!("не удалось открыть {label}: {error}"))?;
    let mut header = [0u8; 4096];
    let read = file
        .read(&mut header)
        .map_err(|error| format!("не удалось прочитать PE-заголовок {label}: {error}"))?;

    if read < 256 {
        return Err(format!(
            "повреждённый PE-файл: слишком короткий заголовок, прочитано {read} байт"
        ));
    }

    if &header[0..2] != b"MZ" {
        if header[0..4] == [0, 0, 0, 0] && &header[4..6] == b"MZ" {
            return Err(
                "повреждённый PE-файл: перед сигнатурой MZ есть 4 лишних нулевых байта".to_string(),
            );
        }
        if header.starts_with(b"version https://git-lfs") {
            return Err("вместо настоящего xray.exe упакован Git LFS pointer; включите checkout lfs:true в GitHub Actions и пересоберите релиз".to_string());
        }
        return Err(format!(
            "повреждённый PE-файл: ожидалась сигнатура MZ, первые байты {:02X} {:02X}",
            header[0], header[1]
        ));
    }

    let pe_offset =
        u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as usize;
    if !(64..=8192).contains(&pe_offset) {
        return Err(format!(
            "повреждённый PE-файл: некорректный offset PE-заголовка {pe_offset}"
        ));
    }
    if pe_offset + 26 > read {
        return Err(format!(
            "повреждённый PE-файл: PE-заголовок обрывается на offset {pe_offset}"
        ));
    }

    if &header[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(format!(
            "повреждённый PE-файл: ожидалась сигнатура PE, получено {:02X} {:02X} {:02X} {:02X}",
            header[pe_offset],
            header[pe_offset + 1],
            header[pe_offset + 2],
            header[pe_offset + 3]
        ));
    }

    let machine = u16::from_le_bytes([header[pe_offset + 4], header[pe_offset + 5]]);
    if machine != PE_MACHINE_AMD64 {
        return Err(format!(
            "неподходящий PE-файл: {label} должен быть Windows x64/AMD64, machine=0x{machine:04X}"
        ));
    }

    let optional_header_magic =
        u16::from_le_bytes([header[pe_offset + 24], header[pe_offset + 25]]);
    if optional_header_magic != PE32_PLUS_MAGIC {
        return Err(format!(
            "неподходящий PE-файл: {label} должен быть PE32+ x64, optional_header=0x{optional_header_magic:04X}"
        ));
    }

    Ok(())
}

pub(crate) fn format_xray_spawn_error(error: &std::io::Error, core_path: &Path) -> String {
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
pub(crate) fn ensure_core_launchable(path: &Path) -> Result<(), String> {
    validate_core_path(path)?;
    let prepared = prepare_core_launch(path, None)?;
    let path = prepared.core.as_path();
    let core_working_dir = path.parent().ok_or("CORE_DIRECTORY_MISSING")?;

    let mut command = Command::new(path);
    command
        .current_dir(core_working_dir)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hide_child_console(&mut command);

    run_command_with_timeout(command, Duration::from_secs(5), "Xray version preflight")?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn ensure_core_launchable(path: &Path) -> Result<(), String> {
    validate_core_path(path)
}

pub(crate) fn validate_core_path(path: &Path) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("не удалось проверить файл: {error}"))?;
    if !metadata.is_file() {
        return Err("это не файл".to_string());
    }
    if metadata.len() < MIN_XRAY_CORE_SIZE_BYTES {
        return Err(format!("слишком маленький файл: {} байт", metadata.len()));
    }
    validate_pe_binary(path, "xray.exe")?;
    verify_core_manifest_artifact(path, "xray.exe")
}

pub(crate) fn is_usable_core_path(path: &Path) -> bool {
    validate_core_path(path).is_ok()
}

pub(crate) fn candidate_core_paths(app: &AppHandle) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(debug_assertions)]
    if let Ok(env_path) = std::env::var("VKARMANI_XRAY_PATH") {
        push_unique_path(&mut paths, PathBuf::from(env_path));
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        // New fixed bundle mapping: tauri.conf.json maps resources directly to $RESOURCE/core/windows.
        push_unique_path(
            &mut paths,
            resource_dir.join("core").join("windows").join("xray.exe"),
        );

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
        push_unique_path(
            &mut paths,
            current_dir.join("src-tauri").join("bin").join("xray.exe"),
        );
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
            push_unique_path(
                &mut paths,
                parent.join("core").join("windows").join("xray.exe"),
            );
        }
    }

    paths
}

pub(crate) fn resolve_core_path(app: &AppHandle) -> Option<PathBuf> {
    candidate_core_paths(app)
        .into_iter()
        .find(|path| is_usable_core_path(path))
}

pub(crate) fn core_not_found_message(app: &AppHandle) -> String {
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
        "Xray-core не найден. В сборке должен быть файл core/windows/xray.exe с корректным core-manifest.json.".to_string()
    } else {
        format!(
            "Xray-core не найден или повреждён. В сборке должен быть файл core/windows/xray.exe с корректным core-manifest.json. Проверенные пути: {candidates}"
        )
    }
}

#[allow(dead_code)]
pub(crate) fn resolve_core_sidecar_path(core_path: &Path, file_name: &str) -> Option<PathBuf> {
    core_path.parent().map(|dir| dir.join(file_name))
}

#[cfg(target_os = "windows")]
pub(crate) fn harden_runtime_output_dir(path: &Path) {
    let path_string = path.to_string_lossy().to_string();
    let path_text = ps_quote(&path_string);
    let script = format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$path = '{}'
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$acl = Get-Acl -LiteralPath $path
$acl.SetAccessRuleProtection($true, $false)
$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($identity in @($user, 'SYSTEM', 'BUILTIN\Administrators')) {{
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, $rights, $inheritance, $propagation, $allow)
  $acl.SetAccessRule($rule)
}}
Set-Acl -LiteralPath $path -AclObject $acl
"#,
        path_text
    );
    let _ = run_powershell(&script);
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn harden_runtime_output_dir(_path: &Path) {}

pub(crate) fn runtime_output_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .or_else(|_| app.path().app_config_dir())
        .map_err(|error| format!("Не удалось определить каталог данных: {error}"))?;

    let path = base.join("runtime");
    fs::create_dir_all(&path)
        .map_err(|error| format!("Не удалось создать runtime каталог: {error}"))?;
    harden_runtime_output_dir(&path);
    Ok(path)
}

pub(crate) fn cleanup_runtime_config_files(_app: &AppHandle) -> Result<(), String> {
    // Other instances may use matching files. Lifecycle removes only its exact config.
    Ok(())
}

pub(crate) fn runtime_log_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(routing_logs_dir(app)?.join("xray-runtime.log"))
}

pub(crate) fn append_runtime_event(app: &AppHandle, line: &str) -> Result<(), String> {
    let log_path = routing_event_log_path(app)?;
    append_log_line(&log_path, "ROUTING", line)
}

pub(crate) fn strip_windows_exe_suffix(value: &str) -> String {
    if value.len() > 4 && value.to_ascii_lowercase().ends_with(".exe") {
        value[..value.len() - 4].to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn extract_executable_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Users can paste either a plain exe name, a full path, or a quoted command
    // like "C:\\Program Files\\App\\app.exe" --flag. Xray process rules must not
    // receive command-line arguments, so keep only the executable part.
    let unwrapped = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.find('"')
            .map(|end| rest[..end].to_string())
            .unwrap_or_else(|| rest.trim_end_matches('"').to_string())
    } else {
        let lower = trimmed.to_ascii_lowercase();
        if let Some(index) = lower.find(".exe") {
            trimmed[..index + 4].to_string()
        } else {
            trimmed.to_string()
        }
    };

    unwrapped.trim().trim_matches('"').to_string()
}

pub(crate) fn normalize_process_match(value: &str) -> Option<String> {
    let executable = extract_executable_value(value);
    let trimmed = executable.trim();
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

pub(crate) fn push_unique_process_match(matches: &mut Vec<String>, candidate: String) -> bool {
    let candidate = candidate.trim().trim_matches('"').to_string();
    if candidate.is_empty() {
        return false;
    }

    // Xray process matching is case-sensitive. Do not deduplicate with
    // eq_ignore_ascii_case here: Windows can report process names/paths with
    // different casing than the file picker, and dropping lowercase variants
    // makes selective TUN silently bypass selected apps.
    if matches.iter().any(|item| item == &candidate) {
        return false;
    }

    matches.push(candidate);
    true
}

pub(crate) fn process_match_candidates(value: &str) -> Vec<String> {
    let Some(normalized) = normalize_process_match(value) else {
        return Vec::new();
    };

    let mut candidates = Vec::new();
    let has_path = normalized.contains('/');

    if has_path {
        // Keep the full path for Xray builds that support process path matching.
        // Xray process matching is case-sensitive, while Windows process/path
        // casing can vary between selection dialogs and runtime lookup.
        push_unique_process_match(&mut candidates, normalized.clone());
        push_unique_process_match(&mut candidates, normalized.to_ascii_lowercase());

        // Some Windows process APIs return paths with backslashes. Add this variant
        // too so a manually selected C:\\...\\app.exe is not silently missed.
        let backslash_path = normalized.replace('/', "\\");
        push_unique_process_match(&mut candidates, backslash_path.clone());
        push_unique_process_match(&mut candidates, backslash_path.to_ascii_lowercase());
    }

    if has_path {
        return candidates;
    } // A full path never expands to all same-named exe files.
    let file_name = normalized
        .rsplit('/')
        .next()
        .unwrap_or(normalized.as_str())
        .trim();

    if !file_name.is_empty() {
        // Xray process routing on Windows is more reliable by executable name than
        // by full path. Keep both original and lowercase spelling because Xray
        // process rules are case-sensitive.
        push_unique_process_match(&mut candidates, file_name.to_string());
        push_unique_process_match(&mut candidates, strip_windows_exe_suffix(file_name));
        let lower_file_name = file_name.to_ascii_lowercase();
        push_unique_process_match(&mut candidates, lower_file_name.clone());
        push_unique_process_match(&mut candidates, strip_windows_exe_suffix(&lower_file_name));
    }

    if !has_path {
        push_unique_process_match(&mut candidates, normalized.clone());
    }

    candidates
}

pub(crate) fn private_bypass_cidrs() -> Vec<&'static str> {
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
