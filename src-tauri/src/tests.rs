use super::*;

#[cfg(test)]
mod regression_cases {
    use super::*;

    #[test]
    fn remote_url_validation_rejects_private_non_https_and_non_vkarmani_targets() {
        assert!(validate_remote_fetch_url("http://sub.vkarmani.com/sub").is_err());
        assert!(validate_remote_fetch_url("https://127.0.0.1/sub").is_err());
        assert!(validate_remote_fetch_url("https://10.0.0.1/sub").is_err());
        assert!(validate_remote_fetch_url("https://[::1]/sub").is_err());
        assert!(validate_remote_fetch_url("https://localhost/sub").is_err());
        assert!(validate_remote_fetch_url("https://1.1.1.1/sub").is_err());
        assert!(validate_remote_fetch_url("https://example.com/sub").is_err());
        assert!(is_allowed_vkarmani_remote_host("vkarmani.com"));
        assert!(is_allowed_vkarmani_remote_host("sub.vkarmani.com"));
        assert!(is_allowed_vkarmani_remote_host("sub.vkarmani.com."));
        assert!(!is_allowed_vkarmani_remote_host("evil-vkarmani.com"));
        assert!(!is_allowed_vkarmani_remote_host(
            "vkarmani.com.evil.example"
        ));
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
            full_config: None,
            primary_outbound_tag: None,
            profile_kind: None,
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
        let output =
            "stat: <\n  name: \"outbound>>>proxy>>>traffic>>>downlink\"\n  value: 123456\n>";
        assert_eq!(parse_xray_stat_value(output), Some(123456));
    }

    fn full_template(config: Value, kind: &str) -> RuntimeTemplate {
        RuntimeTemplate {
            family: "xray".into(),
            protocol: "vless".into(),
            remarks: None,
            outbound: config["outbounds"][0].clone(),
            primary_outbound_tag: Some("pool-a".into()),
            full_config: Some(config),
            profile_kind: Some(kind.into()),
        }
    }

    #[test]
    fn full_config_runtime_keeps_provider_graph_and_scopes_selected_tun_through_loopback() {
        let input: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap();
        for mode in ["proxy", "tun"] {
            let template = full_template(input.clone(), "auto");
            let entries = vec![SplitTunnelEntryPayload {
                kind: "app".into(),
                value: "fixture.exe".into(),
                enabled: true,
                policy: None,
            }];
            let (config, _, _) = build_xray_config(
                &template,
                mode,
                "ipv4",
                (mode == "tun").then_some("192.0.2.15"),
                &entries,
                None,
                None,
            )
            .unwrap();
            validate_full_config_graph(&config).unwrap();
            for key in ["dns", "burstObservatory", "futureExtension"] {
                assert_eq!(config[key], input[key]);
            }
            assert_eq!(
                config["policy"]["levels"]["0"]["handshake"],
                input["policy"]["levels"]["0"]["handshake"]
            );
            assert_eq!(
                config["routing"]["balancers"],
                input["routing"]["balancers"]
            );
            for index in 0..3 {
                let mut actual = config["outbounds"][index].clone();
                if mode == "tun" {
                    assert_eq!(actual["sendThrough"], json!("192.0.2.15"));
                    actual.as_object_mut().unwrap().remove("sendThrough");
                }
                assert_eq!(actual, input["outbounds"][index]);
            }
            let rules = config["routing"]["rules"].as_array().unwrap();
            let provider_auto = rules
                .iter()
                .find(|rule| rule.get("balancerTag").is_some())
                .unwrap();
            assert_eq!(provider_auto["balancerTag"], json!("general-choice"));
            assert!(provider_auto["inboundTag"]
                .as_array()
                .unwrap()
                .iter()
                .all(|tag| tag.as_str().unwrap().contains("profile-")));
            if mode == "tun" {
                let selected = rules
                    .iter()
                    .find(|rule| rule["ruleTag"] == "tun-selected-processes")
                    .unwrap();
                assert!(selected["outboundTag"]
                    .as_str()
                    .unwrap()
                    .ends_with("dispatch-tun"));
                assert!(
                    rules
                        .iter()
                        .position(|rule| rule["ruleTag"] == "tun-selected-processes")
                        .unwrap()
                        < rules
                            .iter()
                            .position(|rule| rule.get("balancerTag").is_some())
                            .unwrap()
                );
            }
            assert_eq!(template.full_config.as_ref().unwrap(), &input);
            if let Some(directory) = std::env::var_os("VKARMANI_CONFIG_CORPUS_OUTPUT") {
                let path = PathBuf::from(directory).join(format!("auto-{mode}.json"));
                fs::write(path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
            }
        }
    }

    #[test]
    fn adapter_tags_do_not_collide_or_join_empty_prefix_balancers() {
        let mut config: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap();
        config["outbounds"].as_array_mut().unwrap().push(json!({"tag":"__vkarmani.direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}));
        config["routing"]["balancers"][0]["selector"] = json!([""]);
        config["log"] = Value::Null;
        config["stats"] = Value::Null;
        config["api"] = json!({"tag":"provider-api","services":["HandlerService"],"future":null});
        config["policy"]["levels"]["0"]["statsUserUplink"] = json!(false);
        let template = full_template(config.clone(), "auto");
        let (runtime, _, _) =
            build_xray_config(&template, "proxy", "ipv4", None, &[], None, None).unwrap();
        validate_full_config_graph(&runtime).unwrap();
        assert_eq!(runtime["outbounds"][3], config["outbounds"][3]);
        assert_eq!(
            runtime["policy"]["levels"]["0"]["statsUserUplink"],
            json!(false)
        );
        assert_eq!(runtime["api"]["future"], Value::Null);
        assert_eq!(runtime["api"]["services"], json!(["StatsService"]));
        assert_eq!(template.full_config.as_ref().unwrap(), &config);
        assert!(runtime["stats"].is_object());
        let selectors = runtime["routing"]["balancers"][0]["selector"]
            .as_array()
            .unwrap();
        assert_eq!(selectors.len(), 4);
        for outbound in runtime["outbounds"].as_array().unwrap().iter().skip(4) {
            let tag = outbound["tag"].as_str().unwrap();
            assert!(!selectors
                .iter()
                .any(|prefix| tag.starts_with(prefix.as_str().unwrap())));
        }
    }

    #[test]
    fn full_config_adapter_failure_never_falls_back_to_one_outbound() {
        let mut input: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap();
        input["api"] = json!({"services":"invalid"});
        let template = full_template(input, "auto");
        assert!(
            build_xray_config(&template, "proxy", "ipv4", None, &[], None, None)
                .err()
                .expect("adapter must fail")
                .contains("fallback")
        );
    }
    #[test]
    fn full_config_api_and_log_owned_fields_reject_go_json_alias_bypasses() {
        for kind in ["auto", "node"] {
            for mode in ["proxy", "tun"] {
                let mut input: Value =
                    serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json"))
                        .unwrap();
                input["api"] = json!({"tag":"provider-api", "services":["StatsService"], "ſervices":["HandlerService"], "serviceſ":["HandlerService"], "Listen":"127.0.0.1:9999", "liſten":"127.0.0.1:9999", "future":{"enabled":false}});
                input["log"] =
                    json!({"acceſs":"synthetic-provider-sink.log", "future":{"enabled":false}});
                let template = full_template(input.clone(), kind);
                let (runtime, _, _) =
                    build_xray_config(&template, mode, "ipv4", None, &[], None, None).unwrap();
                assert_eq!(runtime["api"]["services"], json!(["StatsService"]));
                for alias in ["ſervices", "serviceſ", "Listen", "liſten"] {
                    assert!(
                        runtime["api"].get(alias).is_none(),
                        "Go API field alias survived: {alias}"
                    );
                }
                assert!(runtime["log"].get("acceſs").is_none());
                assert_eq!(runtime["log"]["access"], "none");
                assert_eq!(runtime["api"]["future"], input["api"]["future"]);
                assert_eq!(runtime["log"]["future"], input["log"]["future"]);
                assert_eq!(template.full_config.as_ref().unwrap(), &input);
                if mode == "proxy" && kind == "auto" {
                    if let Some(directory) = std::env::var_os("VKARMANI_CONFIG_CORPUS_OUTPUT") {
                        fs::write(
                            PathBuf::from(directory).join("api-alias-proxy.json"),
                            serde_json::to_vec_pretty(&runtime).unwrap(),
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    #[test]
    fn full_config_owned_fields_remove_equivalent_go_spellings_without_losing_extensions() {
        let mut input: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap();
        input["inboundſ"] = json!([{"listen":"0.0.0.0","port":9999,"protocol":"socks"}]);
        input["outboundſ"] = json!([{"protocol":"freedom","tag":"synthetic-override"}]);
        input["routing"]["ruleſ"] = json!([]);
        input["routing"]["rules"][0]["inboundtag"] = json!([]);
        input["outbounds"][0]["sendthrough"] = json!("127.0.0.2");
        input["api"]["servıces"] = json!({"notAGoAlias":true});
        input["log"] = json!({"Error":"synthetic-provider-sink.log","acceſs":"synthetic-provider-access.log","future":{"enabled":false}});
        for mode in ["proxy", "tun"] {
            let template = full_template(input.clone(), "auto");
            let (runtime, _, _) = build_xray_config(
                &template,
                mode,
                "ipv4",
                (mode == "tun").then_some("192.0.2.15"),
                &[],
                None,
                Some(Path::new("synthetic-client-owned.log")),
            )
            .unwrap();
            for alias in ["inboundſ", "outboundſ"] {
                assert!(runtime.get(alias).is_none());
            }
            assert!(runtime["routing"].get("ruleſ").is_none());
            assert!(runtime["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|rule| rule.get("inboundtag").is_none()));
            if mode == "tun" {
                assert!(runtime["outbounds"][0].get("sendthrough").is_none());
                assert_eq!(runtime["outbounds"][0]["sendThrough"], "192.0.2.15");
            }
            assert!(runtime["log"].get("Error").is_none());
            assert!(runtime["log"].get("acceſs").is_none());
            // Xray logs go to captured stderr; the client owns the file sink.
            assert_eq!(runtime["log"]["error"], "");
            assert_eq!(runtime["api"]["servıces"], input["api"]["servıces"]);
            assert_eq!(runtime["log"]["future"], input["log"]["future"]);
            assert_eq!(template.full_config.as_ref().unwrap(), &input);
        }
    }

    #[test]
    fn full_config_api_alias_properties_cover_case_unicode_null_and_malformed_values() {
        fn aliases(field: &str) -> Vec<String> {
            field
                .chars()
                .fold(vec![String::new()], |prefixes, character| {
                    let mut options = vec![character, character.to_ascii_uppercase()];
                    if character == 's' {
                        options.push('\u{017f}');
                    }
                    prefixes
                        .into_iter()
                        .flat_map(|prefix| {
                            options
                                .iter()
                                .map(move |suffix| format!("{prefix}{suffix}"))
                        })
                        .collect()
                })
        }
        let original: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap();
        let service_aliases = aliases("services");
        let listen_aliases = aliases("listen");
        assert_eq!(service_aliases.len(), 576);
        assert_eq!(listen_aliases.len(), 96);
        for (field, names) in [("services", service_aliases), ("listen", listen_aliases)] {
            for alias in names {
                let mut input = original.clone();
                input["api"] = json!({"tag":"provider-api","future":{"enabled":false}});
                input["api"][&alias] = if field == "services" {
                    json!(["HandlerService"])
                } else {
                    json!("127.0.0.1:9999")
                };
                let template = full_template(input.clone(), "auto");
                let (runtime, _, _) =
                    build_xray_config(&template, "proxy", "ipv4", None, &[], None, None).unwrap();
                assert_eq!(runtime["api"]["services"], json!(["StatsService"]));
                if field == "listen" || alias != "services" {
                    assert!(runtime["api"].get(&alias).is_none());
                }
                assert_eq!(runtime["api"]["future"], input["api"]["future"]);
                assert_eq!(template.full_config.as_ref().unwrap(), &input);
            }
        }
        for alias in ["SERVICES", "ſervices", "serviceſ"] {
            for malformed in [
                json!(0),
                json!("HandlerService"),
                json!({}),
                json!(["StatsService", 0]),
            ] {
                let mut input = original.clone();
                input["api"] = json!({"services":["StatsService"]});
                input["api"][alias] = malformed;
                assert!(build_xray_config(
                    &full_template(input, "auto"),
                    "proxy",
                    "ipv4",
                    None,
                    &[],
                    None,
                    None
                )
                .is_err());
            }
            let mut input = original.clone();
            input["api"] = json!({});
            input["api"][alias] = Value::Null;
            assert!(build_xray_config(
                &full_template(input, "auto"),
                "proxy",
                "ipv4",
                None,
                &[],
                None,
                None
            )
            .is_ok());
        }
    }

    #[test]
    fn imported_mutable_api_services_are_not_client_capabilities_in_any_profile_mode() {
        for kind in ["auto", "node"] {
            for mode in ["proxy", "tun"] {
                let mut input: Value =
                    serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json"))
                        .unwrap();
                input["api"] = json!({"tag":"provider-api","listen":"0.0.0.0:9000","services":["HandlerService","LoggerService","StatsService","ReflectionService"],"future":{"enabled":false}});
                let template = full_template(input.clone(), kind);
                let (runtime, _, _) =
                    build_xray_config(&template, mode, "ipv4", None, &[], None, None).unwrap();
                assert_eq!(runtime["api"]["services"], json!(["StatsService"]));
                assert_eq!(runtime["api"]["future"], input["api"]["future"]);
                assert_eq!(runtime["api"]["tag"], input["api"]["tag"]);
                assert!(runtime["api"].get("listen").is_none());
                let listener = runtime["inbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|inbound| inbound["port"] == XRAY_API_PORT)
                    .unwrap();
                assert_eq!(listener["listen"], "127.0.0.1");
                assert_eq!(template.full_config.as_ref().unwrap(), &input);
                input["api"]["services"] = json!(["StatsService", 0]);
                assert!(build_xray_config(
                    &full_template(input, kind),
                    mode,
                    "ipv4",
                    None,
                    &[],
                    None,
                    None
                )
                .is_err());
            }
        }
    }

    #[test]
    fn full_config_build_is_deterministic_across_100_concurrent_rebuilds() {
        let input: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/xray/auto.json")).unwrap();
        let before = input.clone();
        let hashes = std::thread::scope(|scope| {
            let workers = (0..4)
                .map(|_| {
                    let input = &input;
                    scope.spawn(move || {
                        (0..25)
                            .map(|_| {
                                let template = full_template(input.clone(), "auto");
                                let (config, _, _) = build_xray_config(
                                    &template,
                                    "proxy",
                                    "ipv4",
                                    None,
                                    &[],
                                    None,
                                    None,
                                )
                                .unwrap();
                                validate_full_config_graph(&config).unwrap();
                                sha256_hex_bytes(&serde_json::to_vec(&config).unwrap())
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(hashes.len(), 100);
        assert!(hashes.iter().all(|hash| hash == &hashes[0]));
        assert_eq!(input, before);
    }

    #[test]
    fn proxy_snapshot_parser_trims_registry_values() {
        let status = proxy_status_from_registry_json(
            r#"{"enabled":true,"server":" http=127.0.0.1:10809;https=127.0.0.1:10809 ","bypass":" <local> "}"#,
            "test",
        )
        .expect("proxy json should parse");

        assert!(status.enabled);
        assert_eq!(
            status.server.as_deref(),
            Some("http=127.0.0.1:10809;https=127.0.0.1:10809")
        );
        assert_eq!(status.bypass.as_deref(), Some("<local>"));
        assert!(proxy_snapshot_points_to_runtime(&status));
    }
    #[test]
    fn split_tunnel_path_rule_preserves_exact_path_scope() {
        let candidates =
            process_match_candidates(r#"C:\Program Files\Telegram Desktop\Telegram.exe"#);
        assert!(candidates.iter().any(|item| item.ends_with("Telegram.exe")));
        assert!(candidates
            .iter()
            .all(|item| item.contains('/') || item.contains('\\')));
        assert!(!candidates
            .iter()
            .any(|item| item.eq_ignore_ascii_case("Telegram.exe")));
    }

    #[test]
    fn split_tunnel_quoted_command_keeps_only_executable() {
        let candidates =
            process_match_candidates(r#""C:\Program Files\App\app.exe" --flag --profile test"#);
        assert!(candidates.iter().any(|item| item.ends_with("/app.exe")));
        assert!(candidates
            .iter()
            .all(|item| item.contains('/') || item.contains('\\')));
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
        assert!(plan
            .domain_rules
            .iter()
            .any(|item| item == "regexp:(^|\\.)ru$"));
        assert!(plan
            .domain_rules
            .iter()
            .any(|item| item == "regexp:(^|\\.)xn--p1ai$"));
        assert!(plan
            .domain_rules
            .iter()
            .any(|item| item == "regexp:(^|\\.)example\\.ru$"));
        assert!(plan
            .domain_rules
            .iter()
            .any(|item| item == "domain:bank.ru"));
        assert!(plan.ip_rules.iter().any(|item| item == "1.2.3.4"));
        assert!(plan.ip_rules.iter().any(|item| item == "5.6.7.0/24"));
    }

    #[test]
    fn hysteria2_template_builds_xray_hysteria_v2_without_tcp_sockopt() {
        let template = RuntimeTemplate {
            family: "xray".into(),
            protocol: "hysteria2".into(),
            remarks: Some("HY2 fixture".into()),
            full_config: None,
            primary_outbound_tag: None,
            profile_kind: None,
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

        let (config, _, _) =
            build_xray_config(&template, "proxy", "ipv4", None, &[], None, None).unwrap();
        let outbound = config
            .get("outbounds")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .expect("proxy outbound must exist");

        assert_eq!(
            outbound.get("protocol").and_then(Value::as_str),
            Some("hysteria")
        );
        assert_eq!(
            outbound
                .pointer("/settings/version")
                .and_then(Value::as_i64),
            Some(2)
        );
        assert_eq!(
            outbound
                .pointer("/streamSettings/network")
                .and_then(Value::as_str),
            Some("hysteria")
        );
        assert!(outbound
            .pointer("/streamSettings/hysteriaSettings/auth")
            .is_some());
        assert!(outbound
            .pointer("/streamSettings/udpmasks/0/settings/password")
            .is_some());
        assert!(outbound.pointer("/streamSettings/sockopt").is_none());
    }
}

#[test]
fn native_log_redaction_removes_short_context_credentials_headers_and_full_urls() {
    for secret in [
        "password: abcde",
        "{\"userId\": \"abcde\"}",
        "Authorization: Bearer abcde",
        "Cookie: session=abcde",
        "https://example.com/path/abcde",
    ] {
        assert!(!redact_sensitive(secret).contains("abcde"));
    }
}
