//! Bounded physical-network observation policy. No socket, route or proxy writes.
use super::*;
const STABLE_MS: u64 = 4_000;
const COOLDOWN_MS: u64 = 30_000;
const WINDOW_MS: u64 = 300_000;
const RESUME_GAP_MS: u64 = 12_000;
const SUSPEND_CLOCK_TOLERANCE_MS: u64 = 250;

#[cfg(target_os = "windows")]
pub(crate) fn suspend_elapsed_ms(tick_ms: u64) -> Option<u64> {
    // Same documented Kernel32 ABI as windows-sys. No new dependency feature
    // or power-state write: unbiased interrupt time excludes sleep/hibernation.
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryUnbiasedInterruptTime(time: *mut u64) -> i32;
    }
    let mut awake_100ns = 0u64;
    if unsafe { QueryUnbiasedInterruptTime(&mut awake_100ns) } == 0 {
        return None;
    }
    Some(tick_ms.saturating_sub(awake_100ns / 10_000))
}

pub(crate) enum OwnedRecoveryOutcome<T> {
    Retained(T),
    Started,
    Failed(Box<(T, String)>),
}
pub(crate) fn run_owned_recovery<T>(
    mut runtime: T,
    stop: impl FnOnce(&mut T) -> bool,
    activate: impl FnOnce(T) -> Result<(), Box<(T, String)>>,
) -> OwnedRecoveryOutcome<T> {
    if !stop(&mut runtime) {
        return OwnedRecoveryOutcome::Retained(runtime);
    }
    match activate(runtime) {
        Ok(()) => OwnedRecoveryOutcome::Started,
        Err(error) => OwnedRecoveryOutcome::Failed(error),
    }
}

#[derive(Default)]
pub(crate) struct PhysicalRecoveryPolicy {
    epoch: Option<u64>,
    last_tick: Option<u64>,
    candidate: Option<(DefaultRouteSnapshot, u64)>,
    resume_pending: bool,
    suspend_clock: Option<u64>,
    clock_authoritative: bool,
    attempts: std::collections::VecDeque<u64>,
}
impl PhysicalRecoveryPolicy {
    pub(crate) fn record_suspend_clock(&mut self, total_ms: Option<u64>) {
        self.clock_authoritative = total_ms.is_some();
        if let (Some(prior), Some(current)) = (self.suspend_clock, total_ms) {
            if current.saturating_sub(prior) >= SUSPEND_CLOCK_TOLERANCE_MS {
                self.resume_pending = true;
            }
        }
        self.suspend_clock = total_ms;
    }
    pub(crate) fn observe(
        &mut self,
        now: u64,
        epoch: u64,
        active: &DefaultRouteSnapshot,
        observed: Option<DefaultRouteSnapshot>,
    ) -> bool {
        let resumed = !self.clock_authoritative
            && self
                .last_tick
                .is_some_and(|last| now.saturating_sub(last) >= RESUME_GAP_MS);
        self.last_tick = Some(now);
        if self.epoch != Some(epoch) {
            self.epoch = Some(epoch);
            self.candidate = None;
            self.resume_pending = false;
        } else if resumed {
            self.resume_pending = true;
        }
        while self
            .attempts
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= WINDOW_MS)
        {
            self.attempts.pop_front();
        }
        let Some(observed) = observed else {
            // Lost/unknown physical connectivity is not authority to stop a core
            // or fall back to the VPN adapter. Wait for a stable eligible route.
            self.candidate = None;
            return false;
        };
        if &observed == active && !self.resume_pending {
            self.candidate = None;
            return false;
        }
        match &self.candidate {
            Some((prior, since))
                if prior == &observed && now.saturating_sub(*since) >= STABLE_MS => {}
            Some((prior, _)) if prior == &observed => return false,
            _ => {
                self.candidate = Some((observed, now));
                return false;
            }
        }
        if self.attempts.len() >= 3
            || self
                .attempts
                .back()
                .is_some_and(|at| now.saturating_sub(*at) < COOLDOWN_MS)
        {
            return false;
        }
        self.attempts.push_back(now);
        self.candidate = None;
        self.resume_pending = false;
        true
    }
}

pub(crate) fn rebind_tun_config(
    original: &Value,
    prior: &DefaultRouteSnapshot,
    fresh: &DefaultRouteSnapshot,
) -> Result<Value, String> {
    let valid_ipv4 = |value: &str| {
        value.parse::<Ipv4Addr>().is_ok_and(|ip| {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_link_local()
                && !ip.is_broadcast()
        })
    };
    if fresh.interface_index == 0
        || fresh.interface_luid == 0
        || fresh.interface_alias.is_empty()
        || fresh.interface_alias.len() > 1024
        || fresh.interface_alias.contains('\0')
        || fresh.interface_alias == TUN_INTERFACE_NAME
        || !valid_ipv4(&fresh.source_ip)
        || !valid_ipv4(&fresh.next_hop)
    {
        return Err("NETWORK_BINDING_INVALID".into());
    }
    let mut config = original.clone();
    let inbounds = config["inbounds"]
        .as_array_mut()
        .ok_or("NETWORK_CONFIG_INBOUNDS")?;
    let mut tun_count = 0;
    for inbound in inbounds
        .iter_mut()
        .filter(|inbound| inbound["protocol"] == "tun")
    {
        if inbound["settings"]["autoOutboundsInterface"].as_str() != Some(&prior.interface_alias) {
            return Err("NETWORK_TUN_BINDING_CHANGED".into());
        }
        inbound["settings"]["autoOutboundsInterface"] = json!(fresh.interface_alias);
        tun_count += 1;
    }
    if tun_count != 1 {
        return Err("NETWORK_CONFIG_TUN_COUNT".into());
    }
    for outbound in config["outbounds"]
        .as_array_mut()
        .ok_or("NETWORK_CONFIG_OUTBOUNDS")?
    {
        if matches!(
            outbound["protocol"].as_str(),
            Some("blackhole" | "loopback")
        ) {
            continue;
        }
        if outbound
            .get("sendThrough")
            .is_some_and(|value| value.as_str() != Some(&prior.source_ip))
            || outbound["streamSettings"]["sockopt"]["interface"].as_str()
                != Some(&prior.interface_alias)
        {
            return Err("NETWORK_OUTBOUND_BINDING_CHANGED".into());
        }
        if outbound.get("sendThrough").is_some() {
            outbound["sendThrough"] = json!(fresh.source_ip);
        }
        outbound["streamSettings"]["sockopt"]["interface"] = json!(fresh.interface_alias);
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "windows")]
    #[test]
    fn native_sleep_clock_query_succeeds_without_changing_power_state() {
        let tick = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
        let first = suspend_elapsed_ms(tick).expect("Read-only Kernel32 clock query");
        for _ in 0..32 {
            let tick = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
            let now = suspend_elapsed_ms(tick).unwrap();
            assert!(now.abs_diff(first) < SUSPEND_CLOCK_TOLERANCE_MS);
        }
    }
    #[test]
    fn owned_recovery_failure_stages_never_overlap_or_activate_after_unconfirmed_stop() {
        #[derive(Debug)]
        struct Runtime {
            alive: bool,
        }
        let retained = run_owned_recovery(
            Runtime { alive: true },
            |_| false,
            |_| panic!("must not activate before confirmed stop"),
        );
        assert!(matches!(
            retained,
            OwnedRecoveryOutcome::Retained(Runtime { alive: true })
        ));
        for _ in 0..100 {
            for failure in 0..7 {
                let result = run_owned_recovery(
                    Runtime { alive: true },
                    |old| {
                        assert!(old.alive);
                        old.alive = false;
                        true
                    },
                    |mut old| {
                        assert!(!old.alive);
                        if failure >= 3 {
                            old.alive = true;
                        }
                        if failure < 6 {
                            old.alive = false;
                            Err(Box::new((old, "injected failure".into())))
                        } else {
                            Ok(())
                        }
                    },
                );
                match result {
                    OwnedRecoveryOutcome::Failed(error) => assert!(!error.0.alive),
                    OwnedRecoveryOutcome::Started => assert_eq!(failure, 6),
                    _ => panic!("confirmed stop must advance"),
                }
            }
        }
    }
    fn binding() -> DefaultRouteSnapshot {
        DefaultRouteSnapshot {
            interface_index: 12,
            interface_luid: 1212,
            interface_alias: "Ethernet".into(),
            source_ip: "192.0.2.12".into(),
            next_hop: "192.0.2.1".into(),
            dns_servers: vec!["192.0.2.53".into()],
        }
    }
    #[test]
    fn physical_changes_debounce_and_rate_limit_across_new_runtime_epochs() {
        let active = binding();
        let mut changed = active.clone();
        changed.source_ip = "192.0.2.13".into();
        let mut policy = PhysicalRecoveryPolicy::default();
        assert!(!policy.observe(0, 1, &active, Some(active.clone())));
        assert!(!policy.observe(4000, 1, &active, Some(changed.clone())));
        assert!(policy.observe(8000, 1, &active, Some(changed.clone())));
        // A new child epoch must not reset the storm budget.
        assert!(!policy.observe(12000, 2, &active, Some(changed.clone())));
        assert!(!policy.observe(16000, 2, &active, Some(changed.clone())));
        assert!(policy.observe(40000, 2, &active, Some(changed.clone())));
        assert!(!policy.observe(44000, 3, &active, Some(changed.clone())));
        assert!(policy.observe(72000, 3, &active, Some(changed.clone())));
        for now in (76000..300000).step_by(4000) {
            assert!(!policy.observe(now, 4, &active, Some(changed.clone())));
            assert!(policy.attempts.len() <= 3);
        }
        assert!(policy.observe(312000, 4, &active, Some(changed)));
    }
    #[test]
    fn resume_and_unavailable_routes_do_not_restart_storm_or_borrow_virtual_egress() {
        let active = binding();
        let mut policy = PhysicalRecoveryPolicy::default();
        assert!(!policy.observe(0, 1, &active, Some(active.clone())));
        assert!(!policy.observe(3600000, 1, &active, None));
        assert!(!policy.observe(3604000, 1, &active, Some(active.clone())));
        assert!(policy.observe(3608000, 1, &active, Some(active.clone())));
        for now in (3612000..4000000).step_by(4000) {
            assert!(!policy.observe(now, 2, &active, Some(active.clone())));
        }
    }
    #[test]
    fn suspend_clock_distinguishes_short_sleep_from_awake_scheduler_gap() {
        let active = binding();
        let mut policy = PhysicalRecoveryPolicy::default();
        policy.record_suspend_clock(Some(100));
        assert!(!policy.observe(0, 1, &active, Some(active.clone())));
        policy.record_suspend_clock(Some(115)); // Normal clock-tick precision.
        assert!(!policy.observe(3_600_000, 1, &active, Some(active.clone())));
        policy.record_suspend_clock(Some(915)); // Short actual suspension.
        assert!(!policy.observe(3_604_000, 1, &active, Some(active.clone())));
        policy.record_suspend_clock(Some(916));
        assert!(policy.observe(3_608_000, 1, &active, Some(active.clone())));
        policy.record_suspend_clock(Some(917));
        assert!(!policy.observe(3_612_000, 2, &active, Some(active.clone())));
        policy.record_suspend_clock(None); // OS-query failure uses gap fallback.
        assert!(!policy.observe(3_624_000, 2, &active, Some(active.clone())));
        assert!(!policy.observe(3_628_000, 2, &active, Some(active.clone()))); // Cooldown.
    }
    #[test]
    fn dhcp_dns_gateway_luid_and_alias_each_require_fresh_stable_observation() {
        let active = binding();
        for change in 0..6 {
            let mut next = active.clone();
            match change {
                0 => next.source_ip = "192.0.2.14".into(),
                1 => next.dns_servers = vec!["192.0.2.54".into()],
                2 => next.next_hop = "192.0.2.2".into(),
                3 => next.interface_luid = 1313,
                4 => next.interface_index = 13,
                _ => next.interface_alias = "Wi-Fi".into(),
            }
            let mut policy = PhysicalRecoveryPolicy::default();
            assert!(!policy.observe(0, 1, &active, Some(next.clone())));
            assert!(!policy.observe(4000, 1, &active, None));
            assert!(!policy.observe(8000, 1, &active, Some(next.clone())));
            assert!(policy.observe(12000, 1, &active, Some(next)));
        }
    }
    #[test]
    fn rebind_preserves_provider_graph_policy_and_only_replaces_confirmed_owned_fields() {
        let old = binding();
        let mut next = old.clone();
        next.interface_alias = "Wi-Fi".into();
        next.source_ip = "192.0.2.44".into();
        next.interface_index = 44;
        next.interface_luid = 4444;
        let config = json!({"inbounds":[{"protocol":"tun","settings":{"autoOutboundsInterface":"Ethernet","mtu":1500}}],"outbounds":[{"protocol":"vless","tag":"provider","sendThrough":"192.0.2.12","settings":{"secret":"synthetic"},"streamSettings":{"network":"ws","sockopt":{"interface":"Ethernet","tcpKeepAliveInterval":20}}},{"protocol":"freedom","tag":"direct","sendThrough":"192.0.2.12","streamSettings":{"sockopt":{"interface":"Ethernet"}}},{"protocol":"blackhole","tag":"block"}],"routing":{"balancers":[{"selector":["provider"]}],"rules":[{"outboundTag":"direct","process":["synthetic.exe"]}]}});
        let mut updated = rebind_tun_config(&config, &old, &next).unwrap();
        assert_eq!(
            updated["outbounds"][0]["sendThrough"],
            json!(next.source_ip)
        );
        assert_eq!(
            updated["inbounds"][0]["settings"]["autoOutboundsInterface"],
            json!(next.interface_alias)
        );
        for outbound in updated["outbounds"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .take(2)
        {
            outbound["sendThrough"] = json!(old.source_ip);
            outbound["streamSettings"]["sockopt"]["interface"] = json!(old.interface_alias);
        }
        updated["inbounds"][0]["settings"]["autoOutboundsInterface"] = json!(old.interface_alias);
        assert_eq!(updated, config);
        let mut tampered = config.clone();
        tampered["outbounds"][1]["sendThrough"] = json!("198.51.100.5");
        assert!(rebind_tun_config(&tampered, &old, &next).is_err());
        assert_eq!(
            tampered["outbounds"][0]["sendThrough"],
            config["outbounds"][0]["sendThrough"]
        );
        next.interface_alias = TUN_INTERFACE_NAME.into();
        assert!(rebind_tun_config(&config, &old, &next).is_err());
    }

    #[test]
    fn rebind_preserves_dns_without_sendthrough_and_rejects_ineligible_addresses() {
        let old = binding();
        let config = json!({"inbounds":[{"protocol":"tun","settings":{"autoOutboundsInterface":"Ethernet"}}],"outbounds":[{"protocol":"dns","tag":"dns","settings":{"network":"udp"},"streamSettings":{"sockopt":{"interface":"Ethernet"}}}]});
        let mut fresh = old.clone();
        fresh.source_ip = "192.0.2.42".into();
        let updated = rebind_tun_config(&config, &old, &fresh).unwrap();
        assert!(updated["outbounds"][0].get("sendThrough").is_none());
        assert_eq!(
            updated["outbounds"][0]["settings"],
            config["outbounds"][0]["settings"]
        );
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.10.2",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
        ] {
            fresh.source_ip = ip.into();
            assert!(rebind_tun_config(&config, &old, &fresh).is_err());
            fresh.source_ip = old.source_ip.clone();
            fresh.next_hop = ip.into();
            assert!(rebind_tun_config(&config, &old, &fresh).is_err());
            fresh.next_hop = old.next_hop.clone();
        }
        fresh.interface_alias = "Ethernet\0other".into();
        assert!(rebind_tun_config(&config, &old, &fresh).is_err());
        assert_eq!(
            config["inbounds"][0]["settings"]["autoOutboundsInterface"],
            json!(old.interface_alias)
        );
    }
}
