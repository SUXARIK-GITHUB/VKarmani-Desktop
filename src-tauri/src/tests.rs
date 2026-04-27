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
}

