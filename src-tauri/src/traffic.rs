use super::*;
pub(crate) fn next_telemetry_epoch() -> u64 {
    static EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
pub(crate) fn traffic_runtime_id(runtime: &ManagedCore) -> String {
    format!(
        "{}:{}:{}",
        runtime.child.id(),
        runtime.started_at,
        runtime.telemetry_epoch
    )
}

#[derive(Default)]
pub(crate) struct TrafficAccumulator {
    session_id: u64,
    key: String,
    previous: Option<(u64, u64)>,
    received: u64,
    sent: u64,
    pub(crate) baseline_changed: bool,
}
impl TrafficAccumulator {
    pub(crate) fn start_session(&mut self) -> Result<u64, String> {
        let session_id = self
            .session_id
            .checked_add(1)
            .ok_or("TRAFFIC_SESSION_EXHAUSTED")?;
        *self = Self {
            session_id,
            ..Self::default()
        };
        Ok(session_id)
    }
    pub(crate) fn record(
        &mut self,
        session: u64,
        key: String,
        received: u64,
        sent: u64,
    ) -> Result<(u64, u64), String> {
        if session == 0 || session != self.session_id {
            return Err("TRAFFIC_STALE_SESSION".into());
        }
        // A new source establishes a measured baseline. Never add absolute adapter
        // totals from before this session, or count another runtime's bytes twice.
        if self.key != key {
            self.key = key;
            self.previous = None;
        }
        self.baseline_changed = self
            .previous
            .map_or(true, |(r, s)| received < r || sent < s);
        if let Some((previous_received, previous_sent)) = self.previous {
            // A decreased counter establishes a fresh baseline, not u64 wraparound
            // or a fabricated negative/huge delta. Totals already measured survive.
            self.received = self
                .received
                .saturating_add(received.saturating_sub(previous_received));
            self.sent = self.sent.saturating_add(sent.saturating_sub(previous_sent));
        }
        self.previous = Some((received, sent));
        Ok((self.received, self.sent))
    }
}

pub(crate) fn parse_client_inbound_stats(raw: &str) -> Result<(u64, u64), String> {
    if raw.len() > 256 * 1024 {
        return Err("TRAFFIC_RESPONSE_TOO_LARGE".into());
    }
    let value: Value = serde_json::from_str(raw).map_err(|_| "TRAFFIC_INVALID_JSON")?;
    let object = value.as_object().ok_or("TRAFFIC_INVALID_RESPONSE")?;
    let empty = Vec::new();
    let stats = match object.get("stat") {
        Some(Value::Array(items)) => items,
        None if object.is_empty() => &empty, // Valid protobuf JSON: no registered counters yet.
        _ => return Err("TRAFFIC_INVALID_STATS".into()),
    };
    let mut seen = std::collections::HashSet::new();
    let (mut received, mut sent) = (0u64, 0u64);
    for stat in stats {
        let name = stat
            .get("name")
            .and_then(Value::as_str)
            .ok_or("TRAFFIC_INVALID_NAME")?;
        let parts: Vec<_> = name.split(">>>").collect();
        if parts.len() != 4
            || parts[0] != "inbound"
            || !matches!(parts[1], "http-in" | "socks-in")
            || parts[2] != "traffic"
        {
            continue;
        }
        if !matches!(parts[3], "uplink" | "downlink") {
            continue;
        }
        if !seen.insert(name) {
            return Err("TRAFFIC_DUPLICATE_COUNTER".into());
        }
        // Proto int64 is JSON string; also accept an exact nonnegative JSON integer.
        let counter = match stat.get("value") {
            None => 0, // Protobuf JSON omits a scalar whose value is zero.
            Some(v) => v
                .as_u64()
                .or_else(|| v.as_str()?.parse::<u64>().ok())
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or("TRAFFIC_INVALID_COUNTER")?,
        };
        if parts[3] == "uplink" {
            sent = sent.checked_add(counter).ok_or("TRAFFIC_OVERFLOW")?;
        } else {
            received = received.checked_add(counter).ok_or("TRAFFIC_OVERFLOW")?;
        }
    }
    Ok((received, sent))
}

#[cfg(windows)]
pub(crate) fn tun_counters(alias: &str) -> Result<(String, u64, u64), String> {
    use windows_sys::Win32::NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH};
    let wide: Vec<u16> = alias.encode_utf16().chain(Some(0)).collect();
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let status = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if status != 0 {
        return Err(format!("TUN_INTERFACE_UNAVAILABLE:{status}"));
    }
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = luid;
    let status = unsafe { GetIfEntry2(&mut row) };
    if status != 0 || row.OperStatus != 1 {
        return Err(format!("TUN_COUNTERS_UNAVAILABLE:{status}"));
    }
    Ok((
        format!("tun:{}", unsafe { luid.Value }),
        row.InOctets,
        row.OutOctets,
    ))
}
#[cfg(not(windows))]
pub(crate) fn tun_counters(_alias: &str) -> Result<(String, u64, u64), String> {
    Err("TUN_UNSUPPORTED_PLATFORM".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_counters_have_correct_orientation_and_no_outbound_double_count() {
        let raw = r#"{"stat":[{"name":"inbound>>>http-in>>>traffic>>>uplink","value":"12"},{"name":"inbound>>>socks-in>>>traffic>>>uplink","value":8},{"name":"inbound>>>socks-in>>>traffic>>>downlink","value":"170"},{"name":"outbound>>>proxy>>>traffic>>>uplink","value":"99999"},{"name":"inbound>>>api>>>traffic>>>uplink","value":"99999"}]}"#;
        assert_eq!(parse_client_inbound_stats(raw).unwrap(), (170, 20));
        assert_eq!(parse_client_inbound_stats("{}").unwrap(), (0, 0));
    }
    #[test]
    fn malformed_stats_never_become_zero() {
        for raw in [
            "",
            "null",
            "[]",
            "{\"error\":\"unavailable\"}",
            "{\"stat\":null}",
            "{\"stat\":[{\"name\":\"inbound>>>http-in>>>traffic>>>uplink\",\"value\":-1}]}",
        ] {
            assert!(parse_client_inbound_stats(raw).is_err());
        }
        let item = r#"{"name":"inbound>>>http-in>>>traffic>>>uplink","value":"1"}"#;
        assert!(parse_client_inbound_stats(&format!("{{\"stat\":[{item},{item}]}}")).is_err());
        assert!(parse_client_inbound_stats(&" ".repeat(256 * 1024 + 1)).is_err());
    }
    #[test]
    fn session_preserves_totals_through_reset_switch_and_rejects_old_sessions() {
        let mut a = TrafficAccumulator::default();
        assert_eq!(a.start_session().unwrap(), 1);
        assert_eq!(a.record(1, "core1".into(), 100, 10).unwrap(), (0, 0));
        assert_eq!(a.record(1, "core1".into(), 150, 30).unwrap(), (50, 20));
        assert_eq!(a.record(1, "core1".into(), 2, 1).unwrap(), (50, 20));
        assert_eq!(a.record(1, "core1".into(), 7, 9).unwrap(), (55, 28));
        assert_eq!(a.record(1, "core2".into(), 500, 800).unwrap(), (55, 28));
        assert_eq!(a.record(1, "core2".into(), 508, 811).unwrap(), (63, 39));
        assert_eq!(a.start_session().unwrap(), 2);
        assert_eq!(a.record(2, "core2".into(), 600, 900).unwrap(), (0, 0));
        assert!(a.record(1, "core1".into(), 999, 999).is_err());
    }
    #[test]
    fn saturating_totals_and_many_counter_resets_are_bounded() {
        let mut a = TrafficAccumulator::default();
        a.start_session().unwrap();
        a.record(1, "a".into(), 0, 0).unwrap();
        for _ in 0..1000 {
            a.record(1, "a".into(), u64::MAX, u64::MAX).unwrap();
            a.record(1, "a".into(), 0, 0).unwrap();
        }
        assert_eq!(a.record(1, "a".into(), 1, 1).unwrap(), (u64::MAX, u64::MAX));
    }
    #[test]
    fn generated_counter_events_preserve_monotonic_totals_and_exact_deltas() {
        let mut a = TrafficAccumulator::default();
        let session = a.start_session().unwrap();
        let (mut seed, mut received, mut sent, mut expected_received, mut expected_sent) =
            (719u64, 0u64, 0u64, 0u64, 0u64);
        a.record(session, "same-source".into(), 0, 0).unwrap();
        for i in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let (r, s) = (seed & 4095, (seed >> 16) & 2047);
            if i % 37 == 0 {
                received = 0;
                sent = 0;
                a.record(session, "same-source".into(), 0, 0).unwrap();
            }
            received += r;
            sent += s;
            expected_received += r;
            expected_sent += s;
            assert_eq!(
                a.record(session, "same-source".into(), received, sent)
                    .unwrap(),
                (expected_received, expected_sent)
            );
            assert!(a
                .record(session + 1, "foreign".into(), u64::MAX, u64::MAX)
                .is_err());
        }
    }
    #[test]
    fn negative_json_corpus_is_bounded_and_never_panics() {
        let mut seed = 23u64;
        for length in 0..2000 {
            let mut raw = String::with_capacity(length);
            for _ in 0..length {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                raw.push((32 + (seed % 95) as u8) as char);
            }
            assert!(parse_client_inbound_stats(&raw).is_err());
        }
        assert_eq!(
            parse_client_inbound_stats(
                r#"{"stat":[{"name":"inbound>>>http-in>>>traffic>>>uplink"}]}"#
            )
            .unwrap(),
            (0, 0)
        );
        assert!(parse_client_inbound_stats(r#"{"stat":[{"name":"inbound>>>http-in>>>traffic>>>uplink","value":"9223372036854775808"}]}"#).is_err());
    }
}
