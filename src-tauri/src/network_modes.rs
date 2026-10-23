//! Reject malformed IPC modes before preflight/teardown. TUN policy requires an
//! explicit choice; other missing legacy fields retain their documented defaults.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkMode {
    Proxy,
    Tun,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkIpStack {
    Ipv4,
    Ipv6,
}
fn token(value: Option<&str>, fallback: &str, code: &str) -> Result<String, String> {
    match value {
        None => Ok(fallback.into()),
        Some(value)
            if value.len() <= 16
                && !value.chars().any(char::is_control)
                && !value.trim().is_empty() =>
        {
            Ok(value.trim().to_ascii_lowercase())
        }
        _ => Err(code.into()),
    }
}
impl NetworkMode {
    #[cfg(any(windows, test))]
    pub(crate) fn require_elevation(self, elevated: bool) -> Result<(), String> {
        if self == Self::Tun && !elevated {
            return Err("TUN_ELEVATION_REQUIRED: TUN requires administrator privileges; no runtime teardown or route installation was started".into());
        }
        Ok(())
    }
    pub(crate) fn require_process_enforcement(
        self,
        policy_mode: Option<&str>,
    ) -> Result<&str, String> {
        if self == Self::Tun {
            match policy_mode {
                // Xray26.4.25 returns false on lookup failure. The selected
                // fallback DIRECT can expose protected traffic; no approved
                // OS enforcement backend exists yet.
                Some("selected") => return Err("TUN_PROCESS_ENFORCEMENT_UNAVAILABLE".into()),
                Some("all" | "exclude") => {}
                None => return Err("TUN_POLICY_REQUIRED".into()),
                _ => return Err("TUN_POLICY_INVALID".into()),
            }
        }
        // The legacy fallback is reachable only for Proxy. TUN must have an
        // explicit valid policy above; never invent selected or broaden to all.
        Ok(policy_mode.unwrap_or("selected"))
    }
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, String> {
        match token(value, "proxy", "NETWORK_MODE_INVALID")?.as_str() {
            "proxy" => Ok(Self::Proxy),
            "tun" => Ok(Self::Tun),
            _ => Err("NETWORK_MODE_INVALID".into()),
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Tun => "tun",
        }
    }
}
impl NetworkIpStack {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, String> {
        match token(value, "ipv4", "NETWORK_IP_STACK_INVALID")?.as_str() {
            "ipv4" | "4" => Ok(Self::Ipv4),
            "ipv6" | "6" => Ok(Self::Ipv6),
            _ => Err("NETWORK_IP_STACK_INVALID".into()),
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hotfix078_full_tun_requires_elevation_but_never_changes_selected_admission() {
        assert!(NetworkMode::Proxy.require_elevation(false).is_ok());
        NetworkMode::Tun
            .require_process_enforcement(Some("all"))
            .unwrap();
        assert!(NetworkMode::Tun
            .require_elevation(false)
            .unwrap_err()
            .starts_with("TUN_ELEVATION_REQUIRED"));
        NetworkMode::Tun.require_elevation(true).unwrap();
        for elevated in [false, true] {
            assert_eq!(
                NetworkMode::Tun
                    .require_process_enforcement(Some("selected"))
                    .unwrap_err(),
                "TUN_PROCESS_ENFORCEMENT_UNAVAILABLE"
            );
            assert_eq!(
                NetworkMode::Tun.require_elevation(elevated).is_ok(),
                elevated
            );
        }
    }
    #[test]
    fn selected_tun_fails_before_runtime_admission_without_os_enforcement() {
        assert_eq!(
            NetworkMode::Tun
                .require_process_enforcement(Some("selected"))
                .unwrap_err(),
            "TUN_PROCESS_ENFORCEMENT_UNAVAILABLE"
        );
        assert_eq!(
            NetworkMode::Tun
                .require_process_enforcement(None)
                .unwrap_err(),
            "TUN_POLICY_REQUIRED"
        );
        for policy in [Some("all"), Some("exclude")] {
            NetworkMode::Tun
                .require_process_enforcement(policy)
                .unwrap();
        }
        for policy in [Some("SELECTED"), Some("unknown"), Some(""), Some("all\0")] {
            assert_eq!(
                NetworkMode::Tun
                    .require_process_enforcement(policy)
                    .unwrap_err(),
                "TUN_POLICY_INVALID"
            );
        }
        NetworkMode::Proxy
            .require_process_enforcement(None)
            .unwrap();
    }
    #[test]
    fn legacy_defaults_and_explicit_valid_aliases_remain() {
        assert_eq!(NetworkMode::parse(None).unwrap(), NetworkMode::Proxy);
        assert_eq!(NetworkIpStack::parse(None).unwrap(), NetworkIpStack::Ipv4);
        assert_eq!(NetworkMode::parse(Some(" TUN ")).unwrap().as_str(), "tun");
        for value in ["ipv6", "IPv6", "6"] {
            assert_eq!(NetworkIpStack::parse(Some(value)).unwrap().as_str(), "ipv6");
        }
        assert_eq!(NetworkIpStack::parse(Some("4")).unwrap().as_str(), "ipv4");
    }
    #[test]
    fn supplied_malformed_modes_cannot_silently_become_proxy_or_ipv4() {
        for value in [
            "",
            " ",
            "tun!",
            "typo",
            "\ntun",
            "tun\0",
            "../tun",
            "ＴＵＮ",
            "tun________________________",
        ] {
            assert!(NetworkMode::parse(Some(value)).is_err());
        }
        for value in ["", " ", "7", "ipv5", "ipv4\n", "ipv4\0", "..", "<script>"] {
            assert!(NetworkIpStack::parse(Some(value)).is_err());
        }
    }
    #[test]
    fn generated_invalid_wire_modes_fail_before_any_runtime_action() {
        for n in 0..1000 {
            let value = format!("invalid{n}");
            assert_eq!(
                NetworkMode::parse(Some(&value)).unwrap_err(),
                "NETWORK_MODE_INVALID"
            );
            assert_eq!(
                NetworkIpStack::parse(Some(&value)).unwrap_err(),
                "NETWORK_IP_STACK_INVALID"
            );
        }
    }
}
