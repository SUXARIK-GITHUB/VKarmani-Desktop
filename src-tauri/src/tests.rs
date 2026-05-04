use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_url_validation_rejects_private_and_non_https_targets() {
        assert!(validate_remote_fetch_url("http://1.1.1.1/sub").is_err());
        assert!(validate_remote_fetch_url("https://127.0.0.1/sub").is_err());
        assert!(validate_remote_fetch_url("https://10.0.0.1/sub").is_err());
        assert!(validate_remote_fetch_url("https://[::1]/sub").is_err());
        assert!(validate_remote_fetch_url("https://localhost/sub").is_err());
        assert!(validate_remote_fetch_url("https://1.1.1.1/sub").is_ok());
    }

    #[test]
    fn remnawave_hwid_is_stable_hashed_and_not_raw_device_id() {
        let raw = "123e4567-e89b-12d3-a456-426614174000";
        let first = remnawave_hwid_from_seed(raw).expect("valid seed should produce hwid");
        let second = remnawave_hwid_from_seed(raw).expect("valid seed should produce hwid");

        assert_eq!(first, second);
        assert!(first.starts_with("vkarmani-"));
        assert_eq!(first.len(), "vkarmani-".len() + 32);
        assert!(!first.contains(raw));
        assert!(remnawave_hwid_from_seed("—").is_none());
    }

    #[test]
    fn redaction_masks_vpn_links_and_long_tokens() {
        let input = "connecting vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality token=abcdefghijklmnopqrstuvwxyz1234567890";
        let output = redact_sensitive(input);
        assert!(output.contains("[redacted-vpn-link]"));
        assert!(!output.contains("vless://123e4567"));
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
    }

    #[test]
    fn redaction_masks_query_secrets_and_uuids() {
        let input = "uuid 123e4567-e89b-12d3-a456-426614174000 url https://sub.vkarmani.com/super-secret-path?token=shortSecret&key=abc";
        let output = redact_sensitive(input);
        assert!(!output.contains("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!output.contains("super-secret-path"));
        assert!(!output.contains("token=shortSecret"));
        assert!(!output.contains("key=abc"));
        assert!(output.contains("[redacted-key]") || output.contains("[redacted-secret]"));
    }

    #[test]
    fn runtime_port_validation_keeps_ports_in_u16_range() {
        assert_eq!(value_as_valid_port(&json!(1)), Some(1));
        assert_eq!(value_as_valid_port(&json!(65535)), Some(65535));
        assert_eq!(value_as_valid_port(&json!(0)), None);
        assert_eq!(value_as_valid_port(&json!(70000)), None);

        let template = RuntimeTemplate {
            family: "xray".into(),
            protocol: "vless".into(),
            remarks: None,
            outbound: json!({
                "settings": {
                    "vnext": [{"address": "example.com", "port": 70000}]
                }
            }),
        };

        let (host, port) = extract_outbound_address_and_port(&template);
        assert_eq!(host.as_deref(), Some("example.com"));
        assert_eq!(port, 443);
    }

    #[test]
    fn xray_stat_parser_reads_cli_value() {
        let output = "stat: <\n  name: \"outbound>>>proxy>>>traffic>>>downlink\"\n  value: 123456\n>";
        assert_eq!(parse_xray_stat_value(output), Some(123456));
    }

    #[test]
    fn proxy_snapshot_parser_trims_registry_values() {
        let status = proxy_status_from_registry_json(
            r#"{"enabled":true,"server":" http=127.0.0.1:10809;https=127.0.0.1:10809 ","bypass":" <local> "}"#,
            "test",
        )
        .expect("proxy json should parse");

        assert!(status.enabled);
        assert_eq!(status.server.as_deref(), Some("http=127.0.0.1:10809;https=127.0.0.1:10809"));
        assert_eq!(status.bypass.as_deref(), Some("<local>"));
        assert!(proxy_snapshot_points_to_runtime(&status));
    }
    #[test]
    fn split_tunnel_path_rule_expands_to_process_name_candidates() {
        let candidates = process_match_candidates(r#"C:\Program Files\Telegram Desktop\Telegram.exe"#);
        assert!(candidates.iter().any(|item| item.ends_with("Telegram.exe")));
        assert!(candidates.iter().any(|item| item.eq_ignore_ascii_case("Telegram.exe")));
        assert!(candidates.iter().any(|item| item.eq_ignore_ascii_case("Telegram")));
    }

    #[test]
    fn split_tunnel_quoted_command_keeps_only_executable() {
        let candidates = process_match_candidates(r#""C:\Program Files\App\app.exe" --flag --profile test"#);
        assert!(candidates.iter().any(|item| item.eq_ignore_ascii_case("app.exe")));
        assert!(candidates.iter().any(|item| item.eq_ignore_ascii_case("app")));
        assert!(!candidates.iter().any(|item| item.contains("--flag")));
    }


    #[test]
    fn routing_exclusions_build_direct_domain_and_ip_rules() {
        let exclusions = RoutingExclusionSettingsPayload {
            enabled: true,
            bypass_ru_domains: true,
            bypass_su_domains: false,
            bypass_rf_domains: true,
            domains: vec!["*.example.ru".into(), "https://bank.ru/path".into()],
            ips: vec!["1.2.3.4".into(), "5.6.7.0/24".into()],
        };

        let plan = build_routing_exclusion_rule_plan(Some(&exclusions));
        assert!(plan.domain_rules.iter().any(|item| item == "regexp:(^|\\.)ru$"));
        assert!(plan.domain_rules.iter().any(|item| item == "regexp:(^|\\.)xn--p1ai$"));
        assert!(plan.domain_rules.iter().any(|item| item == "regexp:(^|\\.)example\\.ru$"));
        assert!(plan.domain_rules.iter().any(|item| item == "domain:bank.ru"));
        assert!(plan.ip_rules.iter().any(|item| item == "1.2.3.4"));
        assert!(plan.ip_rules.iter().any(|item| item == "5.6.7.0/24"));
    }

    #[test]
    fn hysteria2_template_builds_xray_hysteria_v2_without_tcp_sockopt() {
        let template = RuntimeTemplate {
            family: "xray".into(),
            protocol: "hysteria2".into(),
            remarks: Some("HY2 fixture".into()),
            outbound: json!({
                "tag": "proxy",
                "protocol": "hysteria",
                "settings": {
                    "version": 2,
                    "address": "hy2.example.com",
                    "port": 443
                },
                "streamSettings": {
                    "network": "hysteria",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "hy2.example.com",
                        "fingerprint": "chrome",
                        "alpn": ["h3"]
                    },
                    "hysteriaSettings": {
                        "version": 2,
                        "auth": "secret"
                    },
                    "udpmasks": [
                        {
                            "type": "salamander",
                            "settings": {
                                "password": "obfs-pass"
                            }
                        }
                    ]
                }
            }),
        };

        let (config, _, _) = build_xray_config(&template, "proxy", "ipv4", None, &[], None, None);
        let outbound = config
            .get("outbounds")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .expect("proxy outbound must exist");

        assert_eq!(outbound.get("protocol").and_then(Value::as_str), Some("hysteria"));
        assert_eq!(outbound.pointer("/settings/version").and_then(Value::as_i64), Some(2));
        assert_eq!(outbound.pointer("/streamSettings/network").and_then(Value::as_str), Some("hysteria"));
        assert!(outbound.pointer("/streamSettings/hysteriaSettings/auth").is_some());
        assert!(outbound.pointer("/streamSettings/udpmasks/0/settings/password").is_some());
        assert!(outbound.pointer("/streamSettings/sockopt").is_none());
    }

}
