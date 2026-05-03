use super::*;

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

fn normalize_remote_user_agent(user_agent: Option<String>) -> Result<String, String> {
    let user_agent = user_agent
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| APP_USER_AGENT.to_string());

    if user_agent.len() > 160 || user_agent.chars().any(|ch| ch == '\r' || ch == '\n') {
        return Err("Некорректный User-Agent для subscription-запроса.".to_string());
    }

    Ok(user_agent)
}

fn should_attach_remnawave_device_headers(url: &reqwest::Url) -> bool {
    url.host_str()
        .map(|host| host.eq_ignore_ascii_case("sub.vkarmani.com"))
        .unwrap_or(false)
}

fn attach_remnawave_device_headers(
    request: reqwest::blocking::RequestBuilder,
    url: &reqwest::Url,
) -> reqwest::blocking::RequestBuilder {
    if !should_attach_remnawave_device_headers(url) {
        return request;
    }

    let (hwid, os_name, os_version, os_build, os_architecture, device_name) = windows_device_info();
    let mut request = request
        .header("x-device-os", os_name)
        .header("x-ver-os", format!("{} {}", os_version, os_build).trim().to_string())
        .header("x-device-model", if device_name.trim().is_empty() || device_name == "—" {
            format!("VKarmani Desktop {os_architecture}")
        } else {
            device_name
        });

    if !hwid.trim().is_empty() && hwid != "—" {
        request = request.header("x-hwid", hwid);
    }

    request
}

#[tauri::command]
pub(crate) fn fetch_remote_text(url: String, accept: Option<String>, user_agent: Option<String>) -> Result<String, String> {
    let client = build_remote_fetch_client(Duration::from_secs(8))?;
    let accept_header = accept.unwrap_or_else(|| "text/plain, application/json, text/html".to_string());
    let user_agent_header = normalize_remote_user_agent(user_agent)?;
    let mut current_url = validate_remote_fetch_url(&url)?;

    for redirect_count in 0..=MAX_REMOTE_FETCH_REDIRECTS {
        let request = client
            .get(current_url.clone())
            .header(reqwest::header::USER_AGENT, user_agent_header.as_str())
            .header(reqwest::header::ACCEPT, accept_header.as_str());
        let response = attach_remnawave_device_headers(request, &current_url)
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
            return Err(format!("HTTP {}", response.status()));
        }

        return read_limited_remote_text(response);
    }

    Err("Слишком много redirects при удалённом fetch.".into())
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

#[tauri::command]
pub(crate) fn revoke_hwid_device(
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
