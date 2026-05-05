use super::*;

pub(crate) fn is_allowed_vkarmani_remote_host(host: &str) -> bool {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    normalized == "vkarmani.com" || normalized.ends_with(".vkarmani.com")
}

pub(crate) fn validate_remote_fetch_url(raw_url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(raw_url)
        .map_err(|_| "Некорректный URL для удалённого запроса.".to_string())?;

    if parsed.scheme() != "https" {
        return Err("Удалённые запросы разрешены только по HTTPS.".into());
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL с userinfo запрещены для удалённого fetch.".into());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL для удалённого fetch должен содержать hostname.".to_string())?
        .trim()
        .to_string();

    if is_forbidden_remote_host_label(&host) {
        return Err("Локальные hostnames запрещены для удалённого fetch.".into());
    }

    if !is_allowed_vkarmani_remote_host(&host) {
        return Err("Удалённый fetch разрешён только для доменов VKarmani (*.vkarmani.com).".into());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_forbidden_remote_ip(ip) {
            return Err("Локальные, приватные и служебные IP-адреса запрещены для удалённого fetch.".into());
        }
        return Ok(parsed);
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "Не удалось определить порт удалённого HTTPS URL.".to_string())?;

    let addrs = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| format!("Не удалось проверить DNS для удалённого fetch: {error}"))?;

    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        if is_forbidden_remote_ip(addr.ip()) {
            return Err("DNS удалённого fetch указывает на локальный, приватный или служебный IP-адрес.".into());
        }
    }

    if !resolved_any {
        return Err("DNS удалённого fetch не вернул ни одного IP-адреса.".into());
    }

    Ok(parsed)
}

pub(crate) fn build_remote_fetch_client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(false)
        .no_proxy()
        .build()
        .map_err(|error| format!("Не удалось создать HTTP client: {error}"))
}

fn is_blank_device_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed == "—" || trimmed.eq_ignore_ascii_case("unknown")
}

pub(crate) fn remnawave_hwid_from_seed(seed: &str) -> Option<String> {
    if is_blank_device_value(seed) {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"vkarmani-remnawave-hwid-v1:");
    hasher.update(seed.trim().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }

    Some(format!("vkarmani-{hex}"))
}

fn current_remnawave_device_identity() -> (String, String, String, String, String, String) {
    let (raw_hwid, os_name, os_version, os_build, os_architecture, device_name) = windows_device_info();
    let fallback_seed = [
        os_name.as_str(),
        os_version.as_str(),
        os_build.as_str(),
        os_architecture.as_str(),
        device_name.as_str(),
    ]
    .iter()
    .filter(|value| !is_blank_device_value(value))
    .copied()
    .collect::<Vec<_>>()
    .join("|");

    let hwid = remnawave_hwid_from_seed(&raw_hwid)
        .or_else(|| remnawave_hwid_from_seed(&fallback_seed))
        .unwrap_or_else(|| "vkarmani-unknown-device".to_string());

    (hwid, os_name, os_version, os_build, os_architecture, device_name)
}

fn clean_header_value(value: &str, fallback: &str) -> String {
    let cleaned = value
        .chars()
        .map(|ch| {
            if ch.is_ascii() && !matches!(ch, '\r' | '\n' | '\0') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches('-')
        .trim()
        .to_string();

    if cleaned.is_empty() || cleaned == "—" {
        fallback.to_string()
    } else {
        cleaned
    }
}

pub(crate) fn current_remnawave_hwid() -> String {
    let (hwid, _, _, _, _, _) = current_remnawave_device_identity();
    hwid
}

fn header_is_true(headers: &reqwest::header::HeaderMap, name: &'static str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "true" || normalized == "1" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn remnawave_hwid_status_error(response: &reqwest::blocking::Response) -> Option<String> {
    let headers = response.headers();
    if header_is_true(headers, "x-hwid-max-devices-reached") || header_is_true(headers, "x-hwid-limit") {
        return Some("Remnawave отклонил подписку: достигнут лимит HWID-устройств для этого ключа. Удалите старое устройство в панели/личном кабинете или увеличьте лимит.".to_string());
    }

    if header_is_true(headers, "x-hwid-not-supported") {
        return Some("Remnawave отклонил подписку: сервер считает, что клиент не передал HWID. Перезапустите VKarmani Desktop и попробуйте обновить профиль ещё раз.".to_string());
    }

    None
}

fn apply_remnawave_subscription_headers(request: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
    let (hwid, os_name, os_version, os_build, os_architecture, device_name) = current_remnawave_device_identity();
    let version_label = if !is_blank_device_value(&os_version) {
        os_version
    } else {
        os_build
    };
    let model = if !is_blank_device_value(&device_name) {
        device_name
    } else {
        format!("VKarmani Desktop {os_architecture}")
    };

    request
        .header("x-hwid", clean_header_value(&hwid, "vkarmani-unknown-device"))
        .header("x-device-os", clean_header_value(&os_name, "Desktop"))
        .header("x-ver-os", clean_header_value(&version_label, "unknown"))
        .header("x-device-model", clean_header_value(&model, "VKarmani Desktop"))
        .header("x-app-version", env!("CARGO_PKG_VERSION"))
}

pub(crate) fn read_limited_remote_text(response: reqwest::blocking::Response) -> Result<String, String> {
    if let Some(length) = response.content_length() {
        if length > MAX_REMOTE_FETCH_BYTES {
            return Err(format!(
                "Ответ remote subscription слишком большой: {length} байт. Лимит: {MAX_REMOTE_FETCH_BYTES} байт."
            ));
        }
    }

    let mut reader = response.take(MAX_REMOTE_FETCH_BYTES + 1);
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .map_err(|error| format!("Не удалось прочитать тело ответа: {error}"))?;

    if text.len() as u64 > MAX_REMOTE_FETCH_BYTES {
        return Err(format!(
            "Ответ remote subscription слишком большой. Лимит: {MAX_REMOTE_FETCH_BYTES} байт."
        ));
    }

    Ok(text)
}

fn fetch_remote_text_blocking(url: String, accept: Option<String>, user_agent: Option<String>) -> Result<String, String> {
    let client = build_remote_fetch_client(Duration::from_secs(8))?;
    let accept_header = accept.unwrap_or_else(|| "text/plain, application/json, text/html".to_string());
    let user_agent_header = user_agent
        .as_deref()
        .map(|value| clean_header_value(value, APP_USER_AGENT))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| APP_USER_AGENT.to_string());
    let mut current_url = validate_remote_fetch_url(&url)?;

    for redirect_count in 0..=MAX_REMOTE_FETCH_REDIRECTS {
        let response = apply_remnawave_subscription_headers(
            client
                .get(current_url.clone())
                .header(reqwest::header::USER_AGENT, user_agent_header.as_str())
                .header(reqwest::header::ACCEPT, accept_header.as_str()),
        )
            .send()
            .map_err(|error| format!("Не удалось получить ответ от {current_url}: {error}"))?;

        if response.status().is_redirection() {
            if redirect_count >= MAX_REMOTE_FETCH_REDIRECTS {
                return Err("Слишком много redirects при удалённом fetch.".into());
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "Redirect без Location запрещён для удалённого fetch.".to_string())?;
            let next_url = current_url
                .join(location)
                .map_err(|_| "Некорректный redirect URL для удалённого fetch.".to_string())?;
            current_url = validate_remote_fetch_url(next_url.as_str())?;
            continue;
        }

        if !response.status().is_success() {
            if let Some(hwid_error) = remnawave_hwid_status_error(&response) {
                return Err(hwid_error);
            }

            return Err(format!("HTTP {}", response.status()));
        }

        return read_limited_remote_text(response);
    }

    Err("Слишком много redirects при удалённом fetch.".into())
}

#[tauri::command]
pub(crate) async fn fetch_remote_text(url: String, accept: Option<String>, user_agent: Option<String>) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || fetch_remote_text_blocking(url, accept, user_agent))
        .await
        .map_err(|error| format!("Удалённый fetch был прерван: {error}"))?
}

pub(crate) fn remnawave_api_token() -> Option<String> {
    [
        "VKARMANI_REMNAWAVE_API_TOKEN",
        "REMNAWAVE_API_TOKEN",
    ]
    .iter()
    .find_map(|name| std::env::var(name).ok())
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

fn revoke_hwid_device_blocking(
    panel_url: String,
    uuid: Option<String>,
    hwid: Option<String>,
    user_uuid: Option<String>,
) -> Result<Value, String> {
    let token = remnawave_api_token().ok_or_else(|| {
        "Для настоящего отзыва устройства настройте runtime env VKARMANI_REMNAWAVE_API_TOKEN или REMNAWAVE_API_TOKEN. В клиент не вшивается admin token Remnawave, чтобы не раскрывать его пользователям.".to_string()
    })?;

    let normalized_uuid = uuid.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let normalized_hwid = hwid.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let normalized_user_uuid = user_uuid.as_deref().map(str::trim).filter(|value| !value.is_empty());

    let body = if let Some(uuid_value) = normalized_uuid {
        json!({ "uuid": uuid_value })
    } else if let (Some(hwid_value), Some(user_uuid_value)) = (normalized_hwid, normalized_user_uuid) {
        json!({
            "hwid": hwid_value,
            "userUuid": user_uuid_value,
        })
    } else {
        return Err("Для отзыва HWID нужен UUID устройства или пара userUuid/HWID из Remnawave.".to_string());
    };

    let endpoint = validate_remote_fetch_url(&panel_url)?
        .join("/api/hwid/devices/delete")
        .map_err(|_| "Не удалось собрать Remnawave HWID endpoint.".to_string())?;
    let endpoint = validate_remote_fetch_url(endpoint.as_str())?;
    let client = build_remote_fetch_client(Duration::from_secs(10))?;

    let send_request = |method: reqwest::Method| -> Result<reqwest::blocking::Response, String> {
        client
            .request(method, endpoint.clone())
            .bearer_auth(token.as_str())
            .header(reqwest::header::USER_AGENT, APP_USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .map_err(|error| format!("Не удалось выполнить Remnawave HWID revoke: {error}"))
    };

    let mut response = send_request(reqwest::Method::DELETE)?;
    if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
        || response.status() == reqwest::StatusCode::NOT_FOUND
    {
        response = send_request(reqwest::Method::POST)?;
    }

    let status = response.status();
    let body_text = read_limited_remote_text(response)?;

    if !status.is_success() {
        let safe_body = redact_sensitive(&body_text);
        return Err(format!("Remnawave HWID revoke вернул HTTP {status}: {safe_body}"));
    }

    if body_text.trim().is_empty() {
        return Ok(json!({ "ok": true }));
    }

    serde_json::from_str(&body_text).map_err(|error| format!("Remnawave вернул невалидный JSON после HWID revoke: {error}"))
}

#[tauri::command]
pub(crate) async fn revoke_hwid_device(
    panel_url: String,
    uuid: Option<String>,
    hwid: Option<String>,
    user_uuid: Option<String>,
) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || revoke_hwid_device_blocking(panel_url, uuid, hwid, user_uuid))
        .await
        .map_err(|error| format!("Отзыв HWID-устройства был прерван: {error}"))?
}
