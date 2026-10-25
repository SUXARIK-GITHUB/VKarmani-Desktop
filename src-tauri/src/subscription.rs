use super::*;

// A freshness lease is not an entitlement expiry. Revalidate the same DPAPI
// credential when stale; never ask the user to log in just because time passed.
const SUBSCRIPTION_RECHECK_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SubscriptionFailure {
    Rejected,
    Unavailable,
    CredentialChanged,
}
impl SubscriptionFailure {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Rejected => "SUBSCRIPTION_REJECTED: подписка отключена, отозвана или истекла.",
            Self::Unavailable => "SUBSCRIPTION_UNAVAILABLE: проверка подписки временно недоступна; сохранённая сессия не удалена. Повторите позже.",
            Self::CredentialChanged => "SESSION_CHANGED: ключ или сессия изменились во время проверки.",
        }.into()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum AuthorizationAction {
    Accept,
    Refresh,
    Reject,
}
fn authorization_action(
    auth: &NativeSessionAuthorization,
    key_hash: &str,
    now: u64,
) -> AuthorizationAction {
    if auth.access_key_hash != key_hash
        || auth.access_key_hash.len() != 64
        || !auth
            .access_key_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit())
    {
        return AuthorizationAction::Reject;
    }
    if auth
        .subscription_expires_at
        .is_some_and(|expiry| expiry <= now)
    {
        return AuthorizationAction::Reject;
    }
    if now < auth.verified_at || now >= auth.refresh_after {
        AuthorizationAction::Refresh
    } else {
        AuthorizationAction::Accept
    }
}

fn subscription_candidates(access_key: &str) -> Result<Vec<String>, SubscriptionFailure> {
    let key =
        parse_remote_fetch_url(access_key).map_err(|_| SubscriptionFailure::CredentialChanged)?;
    if key.host_str() != Some("sub.vkarmani.com")
        || key.port_or_known_default() != Some(443)
        || key.query().is_some()
        || key.fragment().is_some()
    {
        return Err(SubscriptionFailure::CredentialChanged);
    }
    let identifier = key
        .path_segments()
        .and_then(|mut parts| parts.rfind(|part| !part.is_empty()))
        .filter(|id| {
            id.len() >= 5
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
        })
        .ok_or(SubscriptionFailure::CredentialChanged)?;
    let origin = key.origin().ascii_serialization();
    Ok(vec![
        format!("{origin}/api/sub/{identifier}/json"),
        format!("{origin}/api/subscriptions/by-short-uuid/{identifier}/json"),
        format!("{}/json", access_key.trim_end_matches('/')),
    ])
}

// Reject explicit provider denial before accepting an otherwise usable graph.
// Time parsing is deliberately strict: malformed supplied expiry is unavailable,
// never proof of an unlimited subscription.
fn parse_provider_expiry(value: &Value) -> Result<Option<u64>, SubscriptionFailure> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(number) = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
    {
        return Ok((number > 0).then_some(if number > 10_000_000_000 {
            number / 1000
        } else {
            number
        }));
    }
    let text = value.as_str().ok_or(SubscriptionFailure::Unavailable)?;
    // Remnawave UTC ISO date, with optional fractional seconds. Offset forms
    // are not silently misinterpreted as local time.
    if text.len() < 20
        || !text.is_ascii()
        || !text.ends_with('Z')
        || &text[4..5] != "-"
        || &text[7..8] != "-"
        || &text[10..11] != "T"
        || &text[13..14] != ":"
        || &text[16..17] != ":"
    {
        return Err(SubscriptionFailure::Unavailable);
    }
    if text.len() > 20
        && (!text[19..text.len() - 1].starts_with('.')
            || !text[20..text.len() - 1].bytes().all(|c| c.is_ascii_digit()))
    {
        return Err(SubscriptionFailure::Unavailable);
    }
    let number = |start, end| {
        text[start..end]
            .parse::<i64>()
            .map_err(|_| SubscriptionFailure::Unavailable)
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > month_days[(month - 1) as usize]
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return Err(SubscriptionFailure::Unavailable);
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year / 400;
    let yoe = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * shifted_month + 2) / 5 + day - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Ok(Some(
        (days * 86400 + hour * 3600 + minute * 60 + second) as u64,
    ))
}

fn assess_subscription_response(
    response: RemoteSubscriptionResponse,
    now: u64,
) -> Result<Option<u64>, SubscriptionFailure> {
    let root: Value =
        serde_json::from_str(&response.text).map_err(|_| SubscriptionFailure::Unavailable)?;
    let mut expiry = response.expires_at;
    let mut found_profile = false;
    let mut nodes = 0;
    let mut stack = vec![(&root, 0)];
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > 100000 || depth > 64 {
            return Err(SubscriptionFailure::Unavailable);
        }
        match value {
            Value::Object(map) => {
                // Config settings may legitimately contain fields named active
                // or status. Inspect entitlement only on metadata containers.
                if depth == 0 || !map.contains_key("outbounds") {
                    if map
                        .get("status")
                        .and_then(Value::as_str)
                        .is_some_and(|status| {
                            matches!(
                                status.to_ascii_lowercase().as_str(),
                                "disabled"
                                    | "blocked"
                                    | "expired"
                                    | "limited"
                                    | "inactive"
                                    | "revoked"
                            )
                        })
                        || ["disabled", "isDisabled"]
                            .iter()
                            .any(|key| map.get(*key).and_then(Value::as_bool) == Some(true))
                        || ["active", "isActive"]
                            .iter()
                            .any(|key| map.get(*key).and_then(Value::as_bool) == Some(false))
                    {
                        return Err(SubscriptionFailure::Rejected);
                    }
                    for key in [
                        "expireAt",
                        "expiresAt",
                        "expiryAt",
                        "expiryDate",
                        "expire",
                        "expiredAt",
                        "expirationDate",
                    ] {
                        if let Some(value) = map.get(key) {
                            if let Some(value) = parse_provider_expiry(value)? {
                                expiry = Some(expiry.map_or(value, |old| old.min(value)));
                            }
                        }
                    }
                }
                if let Some(outbounds) = map.get("outbounds").and_then(Value::as_array) {
                    validate_full_config_graph(value)
                        .map_err(|_| SubscriptionFailure::Unavailable)?;
                    found_profile |= outbounds.iter().any(|outbound| {
                        outbound
                            .get("protocol")
                            .and_then(Value::as_str)
                            .is_some_and(|protocol| {
                                matches!(
                                    protocol,
                                    "vless"
                                        | "vmess"
                                        | "trojan"
                                        | "shadowsocks"
                                        | "socks"
                                        | "http"
                                        | "hysteria"
                                        | "hysteria2"
                                        | "wireguard"
                                )
                            })
                    });
                } else {
                    stack.extend(map.values().map(|value| (value, depth + 1)));
                }
            }
            Value::Array(items) => stack.extend(items.iter().map(|value| (value, depth + 1))),
            _ => {}
        }
    }
    if expiry.is_some_and(|expiry| expiry <= now) {
        return Err(SubscriptionFailure::Rejected);
    }
    if !found_profile {
        return Err(SubscriptionFailure::Unavailable);
    }
    Ok(expiry)
}

fn verify_stored_subscription(key: &str, now: u64) -> Result<Option<u64>, SubscriptionFailure> {
    let deadline = Instant::now() + Duration::from_secs(12);
    for url in subscription_candidates(key)? {
        if Instant::now() >= deadline {
            break;
        }
        let result = fetch_remote_response_blocking(
            url,
            Some("application/json".into()),
            Some(format!(
                "Xray/26.4.25 VKarmani-Desktop/{}",
                env!("CARGO_PKG_VERSION")
            )),
            deadline,
        );
        match result {
            Ok(response) => match assess_subscription_response(response, now) {
                Ok(expiry) => return Ok(expiry),
                Err(SubscriptionFailure::Rejected) => return Err(SubscriptionFailure::Rejected),
                Err(_) => {}
            },
            Err(error) if error.starts_with("HTTP 401") || error.starts_with("HTTP 403") => {
                return Err(SubscriptionFailure::Rejected)
            }
            Err(_) => {}
        }
    }
    Err(SubscriptionFailure::Unavailable)
}

pub(crate) fn authorize_native_subscription(
    app: &AppHandle,
    state: &tauri::State<AppState>,
    force: bool,
    requested_generation: Option<u64>,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    let lock_deadline = Instant::now() + Duration::from_secs(2);
    let _verification = loop {
        match state.subscription_lock.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(SubscriptionFailure::Unavailable.message())
            }
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() < lock_deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(_) => return Err(SubscriptionFailure::Unavailable.message()),
        }
    };
    let generation = state.authorization_generation.load(Ordering::Acquire);
    if requested_generation.is_some_and(|requested| requested != generation) {
        return Err(SubscriptionFailure::CredentialChanged.message());
    }
    let stored_key = load_access_key_secure_blocking(app.clone())?
        .ok_or_else(|| SubscriptionFailure::CredentialChanged.message())?;
    let hash = sha256_hex_bytes(stored_key.as_bytes());
    let now = unix_timestamp_seconds();
    let previous = state
        .session_authorization
        .lock()
        .map_err(|_| "Не удалось прочитать native-сессию".to_string())?
        .clone();
    if !force {
        if let Some(auth) = &previous {
            match authorization_action(auth, &hash, now) {
                AuthorizationAction::Accept => return Ok(()),
                AuthorizationAction::Reject => {
                    clear_native_session_authorization(state)?;
                    return Err(SubscriptionFailure::Rejected.message());
                }
                AuthorizationAction::Refresh => {}
            }
        } else {
            return Err(SubscriptionFailure::CredentialChanged.message());
        }
    }
    let expires_at = match verify_stored_subscription(&stored_key, now) {
        Ok(value) => value,
        Err(SubscriptionFailure::Rejected) => {
            clear_native_session_authorization(state)?;
            refresh_tray_menu(app);
            return Err(SubscriptionFailure::Rejected.message());
        }
        Err(error) => return Err(error.message()), // no logout/cache erasure for transient errors
    };
    let current_key = load_access_key_secure_blocking(app.clone())?
        .ok_or_else(|| SubscriptionFailure::CredentialChanged.message())?;
    if state.authorization_generation.load(Ordering::Acquire) != generation
        || sha256_hex_bytes(current_key.as_bytes()) != hash
    {
        return Err(SubscriptionFailure::CredentialChanged.message());
    }
    let auth = NativeSessionAuthorization {
        access_key_hash: hash,
        verified_at: now,
        refresh_after: now.saturating_add(SUBSCRIPTION_RECHECK_SECONDS),
        subscription_expires_at: expires_at,
    };
    let mut native_auth = state
        .session_authorization
        .lock()
        .map_err(|_| "Не удалось сохранить native-сессию".to_string())?;
    // Logout increments the generation while holding this same mutex.
    if state.authorization_generation.load(Ordering::Acquire) != generation {
        return Err(SubscriptionFailure::CredentialChanged.message());
    }
    *native_auth = Some(auth);
    *state
        .session_authorized
        .lock()
        .map_err(|_| "Не удалось сохранить авторизацию".to_string())? = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(value: Value, expiry: Option<u64>) -> RemoteSubscriptionResponse {
        RemoteSubscriptionResponse {
            text: value.to_string(),
            expires_at: expiry,
        }
    }
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap()
    }
    #[test]
    fn valid_subscription_tun_after_24_hours_proxy_tun_refreshes_without_login() {
        let hash = "a".repeat(64);
        let start = 1_800_000_000;
        let mut auth = NativeSessionAuthorization {
            access_key_hash: hash.clone(),
            verified_at: start,
            refresh_after: start + SUBSCRIPTION_RECHECK_SECONDS,
            subscription_expires_at: Some(start + 7 * 86400),
        };
        assert_eq!(
            authorization_action(&auth, &hash, start),
            AuthorizationAction::Accept
        ); // TUN gate
        let after = start + 86401;
        assert_eq!(
            authorization_action(&auth, &hash, after),
            AuthorizationAction::Refresh
        ); // old implementation cleared session at 24h
        let expiry =
            assess_subscription_response(response(fixture(), Some(start + 7 * 86400)), after)
                .unwrap();
        auth = NativeSessionAuthorization {
            access_key_hash: hash.clone(),
            verified_at: after,
            refresh_after: after + SUBSCRIPTION_RECHECK_SECONDS,
            subscription_expires_at: expiry,
        };
        assert_eq!(
            authorization_action(&auth, &hash, after),
            AuthorizationAction::Accept
        ); // Proxy gate
        assert_eq!(
            authorization_action(&auth, &hash, after + 1),
            AuthorizationAction::Accept
        ); // TUN gate
           // Pure authorization/clock test, not live Windows network lifecycle.
    }
    #[test]
    fn expired_revoked_malformed_unavailable_and_key_change_never_become_valid() {
        let now = 1_800_000_000;
        assert_eq!(
            assess_subscription_response(response(fixture(), Some(now)), now),
            Err(SubscriptionFailure::Rejected)
        );
        for status in ["EXPIRED", "REVOKED", "DISABLED"] {
            assert_eq!(
                assess_subscription_response(
                    response(json!({"status": status, "configs":[fixture()]}), None),
                    now
                ),
                Err(SubscriptionFailure::Rejected)
            );
        }
        let mut disabled_root = fixture();
        disabled_root["status"] = json!("DISABLED");
        assert_eq!(
            assess_subscription_response(response(disabled_root, None), now),
            Err(SubscriptionFailure::Rejected)
        );
        assert_eq!(
            assess_subscription_response(
                response(json!({"configs":[fixture()], "expireAt":"broken"}), None),
                now
            ),
            Err(SubscriptionFailure::Unavailable)
        );
        assert_eq!(
            assess_subscription_response(response(json!({"status":"ACTIVE"}), None), now),
            Err(SubscriptionFailure::Unavailable)
        );
        let auth = NativeSessionAuthorization {
            access_key_hash: "a".repeat(64),
            verified_at: now,
            refresh_after: now + 900,
            subscription_expires_at: None,
        };
        assert_eq!(
            authorization_action(&auth, &"b".repeat(64), now),
            AuthorizationAction::Reject
        );
        assert_eq!(
            authorization_action(&auth, &"a".repeat(64), now - 1),
            AuthorizationAction::Refresh
        );
    }
    #[test]
    fn provider_expiry_dates_and_exact_credential_endpoint_boundary() {
        assert_eq!(
            parse_provider_expiry(&json!("1970-01-01T00:00:00Z")).unwrap(),
            Some(0)
        );
        assert_eq!(
            parse_provider_expiry(&json!("2026-10-04T00:00:00.000Z")).unwrap(),
            Some(1791072000)
        );
        for value in [
            "2026-02-29T00:00:00Z",
            "2026-10-04T24:00:00Z",
            "2026-10-04T00:00:00+03:00",
        ] {
            assert!(parse_provider_expiry(&json!(value)).is_err());
        }
        let urls = subscription_candidates("https://sub.vkarmani.com/synthetic-key").unwrap();
        assert_eq!(urls.len(), 3);
        for key in [
            "https://sub.vkarmani.com:8443/synthetic",
            "https://sub.vkarmani.com/synthetic?secret=1",
            "https://other.vkarmani.com/synthetic",
            "https://user@sub.vkarmani.com/synthetic",
        ] {
            assert!(subscription_candidates(key).is_err());
        }
    }
}
