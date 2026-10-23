use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OwnedRoute {
    destination: String,
    prefix: u8,
    next_hop: String,
    interface_index: u32,
    #[serde(with = "luid_text")]
    interface_luid: u64,
    metric: u32,
    protocol: i32,
}
mod luid_text {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StoredLuid {
            Text(String),
            Legacy(u64),
        }
        match StoredLuid::deserialize(deserializer)? {
            StoredLuid::Text(value) => value.parse().map_err(serde::de::Error::custom),
            // Published0.13.76 already wrote exact native u64 JSON numbers.
            // Accept them without an IEEE754/JS round-trip; keep new output text.
            StoredLuid::Legacy(value) => Ok(value),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RouteEntry {
    route: OwnedRoute,
    applied: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RouteJournal {
    version: u8,
    owner_pid: u32,
    entries: Vec<RouteEntry>,
}

trait RouteBackend {
    fn read(&mut self, route: &OwnedRoute) -> Result<Option<OwnedRoute>, String>;
    fn create(&mut self, route: &OwnedRoute) -> Result<(), String>;
    fn delete(&mut self, route: &OwnedRoute) -> Result<(), String>;
    fn save(&mut self, journal: &RouteJournal) -> Result<(), String>;
    fn clear(&mut self) -> Result<(), String>;
}

fn valid_owned_route(route: &OwnedRoute) -> bool {
    matches!(
        route.destination.as_str(),
        "0.0.0.0" | "128.0.0.0" | "::" | "8000::"
    ) && route.prefix == 1
        && route.interface_index > 0
        && route.interface_luid > 0
        && route.metric == 6
        && route.protocol == 3
        && route
            .destination
            .parse::<IpAddr>()
            .is_ok_and(|ip| route.next_hop == if ip.is_ipv4() { "0.0.0.0" } else { "::" })
}

fn cleanup_routes(
    backend: &mut impl RouteBackend,
    journal: &mut RouteJournal,
) -> Result<(), String> {
    for index in (0..journal.entries.len()).rev() {
        let entry = &journal.entries[index];
        match backend.read(&entry.route)? {
            None => {},
            Some(current) if current == entry.route && entry.applied => {
                backend.delete(&entry.route)?;
                if backend.read(&entry.route)?.is_some() {
                    return Err("ROUTE_CLEANUP_UNCONFIRMED: маршрут остался после удаления.".into());
                }
            },
            Some(_) => return Err("ROUTE_OWNER_CHANGED: маршрут изменён или подготовлен без доказанного владения; сохранён для проверки.".into()),
        }
        journal.entries.remove(index);
        backend.save(journal)?;
    }
    backend.clear()
}

fn install_routes(
    backend: &mut impl RouteBackend,
    journal: &mut RouteJournal,
    routes: &[OwnedRoute],
    mut check_operation: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    for route in routes {
        check_operation()?;
        if !valid_owned_route(route) {
            return Err("ROUTE_INVALID: недопустимый owned route.".into());
        }
        if backend.read(route)?.is_some() {
            return Err(
                "ROUTE_CONFLICT: маршрут уже существует; чужой маршрут не заменяется.".into(),
            );
        }
        journal.entries.push(RouteEntry {
            route: route.clone(),
            applied: false,
        });
        backend.save(journal)?; // Durable intent before the OS mutation.
        check_operation()?;
        if let Err(error) = backend.create(route) {
            // Failed Create does not confer ownership, even if another writer won the race.
            journal.entries.pop();
            backend.save(journal)?;
            return Err(error);
        }
        // Retain this invocation's successful Create even if readback fails.
        // The durable intent remains false until confirmed and saved; it must
        // never grant delete authority to a later process after a crash.
        journal.entries.last_mut().expect("route intent").applied = true;
        if backend.read(route)?.as_ref() != Some(route) {
            return Err("ROUTE_CREATE_UNCONFIRMED: запись не совпала с запросом.".into());
        }
        // All failure paths use cleanup_routes, which verifies actual deletion
        // before forgetting an owned entry. A successful delete call alone is
        // not confirmation, and a failed save must not bypass that invariant.
        backend.save(journal)?;
        check_operation()?;
    }
    Ok(())
}

fn validate_route_interface(
    route: &OwnedRoute,
    identity: Option<(u32, u64, String)>,
) -> Result<bool, String> {
    match identity {
        // The original LUID disappeared. Its routes are absent, even if a new
        // adapter reused the old numeric index. This confers no delete authority.
        None => Ok(false),
        Some((index, luid, alias))
            if index == route.interface_index
                && luid == route.interface_luid
                && alias == TUN_INTERFACE_NAME =>
        {
            Ok(true)
        }
        Some(_) => Err(
            "ROUTE_INTERFACE_CHANGED: original adapter identity changed; journal retained.".into(),
        ),
    }
}
fn require_interface_up(status: i32) -> Result<(), String> {
    if status == 1 {
        Ok(())
    } else {
        Err("TUN_INTERFACE_NOT_READY: adapter is not operational".into())
    }
}
fn complete_route_set(backend: &mut impl RouteBackend, journal: &RouteJournal) -> bool {
    journal.entries.len() == 4
        && journal
            .entries
            .iter()
            .map(|e| e.route.destination.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 4
        && route_journal_status(backend, journal) == "confirmed"
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND},
        NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
        Networking::WinSock::*,
        System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        },
    };

    pub(super) fn interface_identity(index: u32) -> Result<(u64, String), String> {
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = index;
        let status = unsafe { GetIfEntry2(&mut row) };
        if status != 0 {
            return Err(format!("Не удалось проверить интерфейс: Win32 {status}."));
        }
        let end = row
            .Alias
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(row.Alias.len());
        Ok((
            unsafe { row.InterfaceLuid.Value },
            String::from_utf16_lossy(&row.Alias[..end]),
        ))
    }
    pub(super) fn find_index(alias: &str) -> Result<u32, String> {
        let wide: Vec<u16> = alias.encode_utf16().chain(Some(0)).collect();
        if wide[..wide.len() - 1].contains(&0) {
            return Err("Invalid interface alias".into());
        }
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        let status = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
        if status != 0 {
            return Err(format!("Interface lookup: Win32 {status}"));
        }
        let mut index = 0;
        let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if status != 0 || index == 0 {
            return Err(format!("Interface index: Win32 {status}"));
        }
        let (_, actual) = interface_identity(index)?;
        if actual != alias {
            return Err("Interface alias mismatch".into());
        }
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceLuid = luid;
        if unsafe { GetIfEntry2(&mut row) } != 0 || row.InterfaceIndex != index {
            return Err("TUN_INTERFACE_NOT_READY: adapter identity changed".into());
        }
        require_interface_up(row.OperStatus)?;
        // Wintun presence/OperStatus alone says nothing about Windows source
        // address selection. Xray must finish assigning both sink addresses
        // before our journal installs IPv4/IPv6 split routes.
        for prefix in [TUN_GATEWAY_IPV4, TUN_GATEWAY_IPV6] {
            let ip = prefix.split('/').next().ok_or("TUN_ADDRESS_NOT_READY")?;
            let mut unicast: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
            unsafe { InitializeUnicastIpAddressEntry(&mut unicast) };
            unicast.InterfaceLuid = luid;
            unicast.InterfaceIndex = index;
            unicast.Address = address(ip)?;
            let result = unsafe { GetUnicastIpAddressEntry(&mut unicast) };
            require_tun_address_ready(
                result,
                unicast.InterfaceIndex,
                unsafe { unicast.InterfaceLuid.Value },
                unicast.DadState,
                index,
                unsafe { luid.Value },
            )?;
        }
        Ok(index)
    }
    fn require_tun_address_ready(
        status: u32,
        index: u32,
        luid: u64,
        dad: i32,
        expected_index: u32,
        expected_luid: u64,
    ) -> Result<(), String> {
        if status != 0
            || index != expected_index
            || luid != expected_luid
            || dad != IpDadStatePreferred
        {
            return Err("TUN_ADDRESS_NOT_READY: Xray adapter IP addresses are absent, tentative, duplicate or belong to another interface".into());
        }
        Ok(())
    }
    #[test]
    fn hotfix078_address_readiness_rejects_missing_tentative_duplicate_and_reused_index() {
        assert!(require_tun_address_ready(0, 17, 99, IpDadStatePreferred, 17, 99).is_ok());
        for (status, index, luid, dad) in [
            (1168, 17, 99, IpDadStatePreferred),
            (0, 17, 99, IpDadStateTentative),
            (0, 17, 99, IpDadStateDuplicate),
            (0, 17, 100, IpDadStatePreferred),
            (0, 18, 99, IpDadStatePreferred),
        ] {
            assert!(require_tun_address_ready(status, index, luid, dad, 17, 99)
                .unwrap_err()
                .starts_with("TUN_ADDRESS_NOT_READY"));
        }
    }
    fn original_interface(route: &OwnedRoute) -> Result<bool, String> {
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        // Resolve ONLY the recorded LUID, never a possibly recycled index.
        row.InterfaceLuid.Value = route.interface_luid;
        let status = unsafe { GetIfEntry2(&mut row) };
        if status == ERROR_FILE_NOT_FOUND {
            return validate_route_interface(route, None);
        }
        if status != 0 {
            return Err(format!("ROUTE_INTERFACE_UNAVAILABLE: Win32 {status}"));
        }
        let end = row
            .Alias
            .iter()
            .position(|c| *c == 0)
            .ok_or("ROUTE_INTERFACE_UNAVAILABLE")?;
        let alias =
            String::from_utf16(&row.Alias[..end]).map_err(|_| "ROUTE_INTERFACE_UNAVAILABLE")?;
        validate_route_interface(
            route,
            Some((
                row.InterfaceIndex,
                unsafe { row.InterfaceLuid.Value },
                alias,
            )),
        )
    }
    fn address(ip: &str) -> Result<SOCKADDR_INET, String> {
        let mut value: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        match ip
            .parse::<IpAddr>()
            .map_err(|_| "Некорректный route IP".to_string())?
        {
            IpAddr::V4(ip) => {
                value.Ipv4.sin_family = AF_INET;
                value.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            }
            IpAddr::V6(ip) => {
                value.Ipv6.sin6_family = AF_INET6;
                value.Ipv6.sin6_addr.u.Byte = ip.octets();
            }
        }
        Ok(value)
    }
    fn row(route: &OwnedRoute) -> Result<MIB_IPFORWARD_ROW2, String> {
        let mut value: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe {
            InitializeIpForwardEntry(&mut value);
        }
        value.InterfaceLuid = NET_LUID_LH {
            Value: route.interface_luid,
        };
        value.InterfaceIndex = route.interface_index;
        value.DestinationPrefix.Prefix = address(&route.destination)?;
        value.DestinationPrefix.PrefixLength = route.prefix;
        value.NextHop = address(&route.next_hop)?;
        value.Metric = route.metric;
        value.Protocol = route.protocol;
        Ok(value)
    }
    pub(super) struct WindowsRoutes {
        path: PathBuf,
    }
    impl RouteBackend for WindowsRoutes {
        fn read(&mut self, route: &OwnedRoute) -> Result<Option<OwnedRoute>, String> {
            if !original_interface(route)? {
                return Ok(None);
            }
            let mut value = row(route)?;
            let status = unsafe { GetIpForwardEntry2(&mut value) };
            if status == ERROR_NOT_FOUND {
                return Ok(None);
            }
            if status != 0 {
                return Err(format!("Route query: Win32 {status}."));
            }
            let mut current = route.clone();
            current.metric = value.Metric;
            current.protocol = value.Protocol;
            current.interface_index = value.InterfaceIndex;
            current.interface_luid = unsafe { value.InterfaceLuid.Value };
            Ok(Some(current))
        }
        fn create(&mut self, route: &OwnedRoute) -> Result<(), String> {
            if !original_interface(route)? {
                return Err("TUN_INTERFACE_NOT_READY: adapter disappeared".into());
            }
            let mut interface: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
            interface.InterfaceLuid.Value = route.interface_luid;
            if unsafe { GetIfEntry2(&mut interface) } != 0 {
                return Err("TUN_INTERFACE_NOT_READY".into());
            }
            require_interface_up(interface.OperStatus)?;
            let status = unsafe { CreateIpForwardEntry2(&row(route)?) };
            if status == 0 {
                Ok(())
            } else {
                Err(format!("Route create: Win32 {status}."))
            }
        }
        fn delete(&mut self, route: &OwnedRoute) -> Result<(), String> {
            let status = unsafe { DeleteIpForwardEntry2(&row(route)?) };
            if status == 0 {
                Ok(())
            } else {
                Err(format!("Route delete: Win32 {status}."))
            }
        }
        fn save(&mut self, journal: &RouteJournal) -> Result<(), String> {
            let text = serde_json::to_string(journal)
                .map_err(|_| "Route journal serialization".to_string())?;
            atomic_write_text(&self.path, &encrypt_access_key(&text)?, "Owned routes")
        }
        fn clear(&mut self) -> Result<(), String> {
            match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err("Route journal removal failed".into()),
            }
        }
    }
    pub(super) fn backend(app: &AppHandle) -> Result<WindowsRoutes, String> {
        Ok(WindowsRoutes {
            path: runtime_output_dir(app)?.join("owned-tun-routes-v1.dpapi"),
        })
    }
    pub(super) fn read_only_backend(app: &AppHandle) -> Result<WindowsRoutes, String> {
        Ok(WindowsRoutes {
            path: runtime_output_path(app)?.join("owned-tun-routes-v1.dpapi"),
        })
    }
    pub(super) fn load(backend: &WindowsRoutes) -> Result<Option<RouteJournal>, String> {
        // Absence is authoritative only after guarding the parent and exact
        // file handle. Never follow a reparse/hardlink or turn an IO denial
        // into an empty ownership journal via Path::exists().
        let Some(ciphertext) = crate::persistence::read_state_file(&backend.path, 32768)
            .map_err(|_| "ROUTE_JOURNAL_UNAVAILABLE".to_string())?
        else {
            return Ok(None);
        };
        let text = decrypt_access_key(&ciphertext)?;
        let journal: RouteJournal =
            serde_json::from_str(&text).map_err(|_| "Route journal corrupt".to_string())?;
        if journal.version != 1
            || journal.entries.len() > 4
            || journal.entries.iter().any(|e| !valid_owned_route(&e.route))
        {
            return Err("Route journal invalid".into());
        }
        if journal.owner_pid != std::process::id() {
            // Conservatively refuse when a previous owner may still exist. No PID termination.
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    journal.owner_pid,
                )
            };
            if !handle.is_null() {
                let alive = unsafe { WaitForSingleObject(handle, 0) } != 0;
                unsafe {
                    CloseHandle(handle);
                }
                if alive {
                    return Err("ROUTE_OWNER_ACTIVE: предыдущий owner process ещё активен.".into());
                }
            } else if std::io::Error::last_os_error().raw_os_error() != Some(87) {
                return Err("ROUTE_OWNER_UNKNOWN: невозможно проверить предыдущий process.".into());
            }
        }
        // Query the original LUID. Index reuse is not a new adapter's ownership.
        // Only documented absence permits retiring a journal; query errors fail closed.
        for entry in &journal.entries {
            original_interface(&entry.route)?;
        }
        Ok(Some(journal))
    }
    pub(super) fn cleanup(app: &AppHandle) -> Result<(), String> {
        let mut backend = backend(app)?;
        if let Some(mut journal) = load(&backend)? {
            cleanup_routes(&mut backend, &mut journal)?;
        }
        Ok(())
    }
    pub(super) fn configure(app: &AppHandle, interface_name: &str) -> Result<(), String> {
        cleanup(app)?;
        let index = wait_for_tun_interface(interface_name, || {
            check_current_operation(&app.state::<AppState>())
        })?;
        let (luid, alias) = interface_identity(index)?;
        if alias != TUN_INTERFACE_NAME {
            return Err("Неподтверждённый TUN interface".into());
        }
        let routes = ["0.0.0.0", "128.0.0.0", "::", "8000::"]
            .into_iter()
            .map(|ip| OwnedRoute {
                destination: ip.into(),
                prefix: 1,
                next_hop: if ip.contains(':') { "::" } else { "0.0.0.0" }.into(),
                interface_index: index,
                interface_luid: luid,
                metric: 6,
                protocol: 3,
            })
            .collect::<Vec<_>>();
        let mut backend = backend(app)?;
        let mut journal = RouteJournal {
            version: 1,
            owner_pid: std::process::id(),
            entries: Vec::new(),
        };
        if let Err(error) = install_routes(&mut backend, &mut journal, &routes, || {
            check_current_operation(&app.state::<AppState>())
        }) {
            return Err(match cleanup_routes(&mut backend, &mut journal) {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; rollback: {cleanup}"),
            });
        }
        Ok(())
    }
    pub(super) fn confirm_ready(app: &AppHandle) -> Result<(), String> {
        let index = find_index(TUN_INTERFACE_NAME)?;
        let mut backend = read_only_backend(app)?;
        let journal = load(&backend)?.ok_or("TUN_ROUTES_UNCONFIRMED")?;
        if journal
            .entries
            .iter()
            .any(|entry| entry.route.interface_index != index)
            || !complete_route_set(&mut backend, &journal)
        {
            return Err("TUN_ROUTES_UNCONFIRMED: incomplete or changed owned route set".into());
        }
        Ok(())
    }
    #[test]
    fn linked_route_journal_cannot_supply_cleanup_authority() {
        let directory = std::env::temp_dir().join(format!(
            "vkarmani-journal-links-{}-{}",
            std::process::id(),
            crate::durable_state::random_state_id().unwrap()
        ));
        fs::create_dir(&directory).unwrap();
        let original = directory.join("original.dpapi");
        let linked = directory.join("owned-tun-routes-v1.dpapi");
        let text = encrypt_access_key(
            &serde_json::to_string(&RouteJournal {
                version: 1,
                owner_pid: std::process::id(),
                entries: vec![],
            })
            .unwrap(),
        )
        .unwrap();
        fs::write(&original, &text).unwrap();
        assert!(load(&WindowsRoutes {
            path: original.clone()
        })
        .unwrap()
        .is_some());
        fs::hard_link(&original, &linked).unwrap();
        let result = load(&WindowsRoutes {
            path: linked.clone(),
        });
        assert_eq!(fs::read_to_string(&original).unwrap(), text);
        fs::remove_file(linked).unwrap();
        fs::remove_file(original).unwrap();
        fs::remove_dir(directory).unwrap();
        assert!(
            result.is_err(),
            "A hardlinked journal must not authorize cleanup: {result:?}"
        );
    }
    #[test]
    fn missing_route_journal_under_junction_is_not_proven_absence() {
        let directory = std::env::temp_dir().join(format!(
            "vkarmani-journal-junction-{}-{}",
            std::process::id(),
            crate::durable_state::random_state_id().unwrap()
        ));
        let target = directory.join("target");
        let link = directory.join("link");
        fs::create_dir_all(&target).unwrap();
        let mut command = Command::new(
            system_program("reg")
                .unwrap()
                .parent()
                .unwrap()
                .join("cmd.exe"),
        );
        command
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target);
        run_command_with_timeout(
            command,
            Duration::from_secs(3),
            "owned route journal junction",
        )
        .unwrap();
        let result = load(&WindowsRoutes {
            path: link.join("missing.dpapi"),
        });
        fs::remove_dir(link).unwrap();
        fs::remove_dir(target).unwrap();
        fs::remove_dir(directory).unwrap();
        assert!(
            result.is_err(),
            "An untrusted parent must not be interpreted as missing ownership: {result:?}"
        );
    }
    #[test]
    fn retired_luid_does_not_borrow_reused_physical_index_or_block_journal_retirement() {
        // Only OS queries and an owned temp DPAPI journal. Never create/delete a route.
        let physical = default_route_snapshot().unwrap();
        let retired_luid = (6u64 << 48) | (0xFFFFFEu64 << 24);
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceLuid.Value = retired_luid;
        assert_eq!(
            unsafe { GetIfEntry2(&mut row) },
            windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND
        );
        let directory = std::env::temp_dir().join(format!(
            "vkarmani-route-reuse-{}-{}",
            std::process::id(),
            crate::durable_state::random_state_id().unwrap()
        ));
        // Match production's dedicated runtime directory, instead of putting
        // an AppData-shaped journal directly in the shared Temp namespace.
        fs::create_dir(&directory).unwrap();
        let foreign = directory.join("preserve-synthetic.txt");
        fs::write(&foreign, b"preserve").unwrap();
        let path = directory.join("owned-tun-routes-v1.dpapi");
        let mut backend = WindowsRoutes { path: path.clone() };
        backend
            .save(&RouteJournal {
                version: 1,
                owner_pid: std::process::id(),
                entries: vec![RouteEntry {
                    applied: true,
                    route: OwnedRoute {
                        destination: "0.0.0.0".into(),
                        prefix: 1,
                        next_hop: "0.0.0.0".into(),
                        interface_index: physical.interface_index,
                        interface_luid: retired_luid,
                        metric: 6,
                        protocol: 3,
                    },
                }],
            })
            .unwrap();
        let loaded = load(&backend);
        fs::remove_file(path).unwrap();
        assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
        fs::remove_file(foreign).unwrap();
        fs::remove_dir(directory).unwrap();
        assert!(loaded.is_ok(), "A missing original LUID cannot confer authority over the reused index, or block retiring an absent route: {loaded:?}");
    }
    #[test]
    fn read_only_native_route_query() {
        let mut table = null_mut();
        assert_eq!(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) }, 0);
        assert!(!table.is_null());
        unsafe {
            FreeMibTable(table.cast());
        }
    }
}

pub(crate) fn cleanup_tun_routes_for_app(
    app: &AppHandle,
    _interface_name: &str,
    _server_ips: &[String],
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows::cleanup(app)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        Ok(())
    }
}
#[cfg(target_os = "windows")]
pub(crate) fn owned_interface_index(alias: &str) -> Result<u32, String> {
    windows::find_index(alias)
}
pub(crate) fn configure_tun_routes(
    app: &AppHandle,
    interface_name: &str,
    _server_ips: &[String],
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows::configure(app, interface_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (app, interface_name);
        Err("Windows TUN only".into())
    }
}
pub(crate) fn confirm_tun_routes_ready(app: &AppHandle) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows::confirm_ready(app)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        Err("Windows TUN only".into())
    }
}
fn route_journal_status(backend: &mut impl RouteBackend, journal: &RouteJournal) -> &'static str {
    if journal.entries.iter().any(|entry| !entry.applied) {
        return "unconfirmed";
    }
    for entry in &journal.entries {
        match backend.read(&entry.route) {
            Ok(Some(route)) if route == entry.route => {}
            Ok(None) => return "missing",
            Ok(Some(_)) => return "changed",
            Err(_) => return "unavailable",
        }
    }
    "confirmed"
}
pub(crate) fn owned_route_summary(app: &AppHandle) -> (String, Vec<OwnedRoute>) {
    #[cfg(target_os = "windows")]
    {
        match windows::read_only_backend(app).and_then(|backend| windows::load(&backend)) {
            Ok(None) => ("none".into(), vec![]),
            Ok(Some(journal)) => {
                let mut query = match windows::read_only_backend(app) {
                    Ok(value) => value,
                    Err(_) => return ("unavailable".into(), vec![]),
                };
                let status = route_journal_status(&mut query, &journal);
                (
                    status.into(),
                    journal.entries.into_iter().map(|e| e.route).collect(),
                )
            }
            Err(_) => ("unavailable".into(), vec![]),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        ("unsupported".into(), vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake {
        routes: Vec<OwnedRoute>,
        journal: Option<RouteJournal>,
        creates: usize,
        deletes: usize,
        fail_create: Option<usize>,
        fail_save: bool,
        fail_delete: bool,
        reads: usize,
        fail_read_at: Option<usize>,
        saves: usize,
        fail_save_at: Option<usize>,
        delete_noop: bool,
        fail_clear: bool,
    }
    impl RouteBackend for Fake {
        fn read(&mut self, route: &OwnedRoute) -> Result<Option<OwnedRoute>, String> {
            self.reads += 1;
            if self.fail_read_at == Some(self.reads) {
                return Err("injected route query".into());
            }
            Ok(self
                .routes
                .iter()
                .find(|r| {
                    r.destination == route.destination && r.interface_luid == route.interface_luid
                })
                .cloned())
        }
        fn create(&mut self, r: &OwnedRoute) -> Result<(), String> {
            self.creates += 1;
            if self.fail_create == Some(self.creates) {
                return Err("injected create".into());
            }
            self.routes.push(r.clone());
            Ok(())
        }
        fn delete(&mut self, r: &OwnedRoute) -> Result<(), String> {
            if self.fail_delete {
                return Err("injected delete".into());
            }
            self.deletes += 1;
            if !self.delete_noop {
                self.routes.retain(|x| x != r);
            }
            Ok(())
        }
        fn save(&mut self, j: &RouteJournal) -> Result<(), String> {
            self.saves += 1;
            if self.fail_save || self.fail_save_at == Some(self.saves) {
                return Err("injected disk".into());
            }
            self.journal = Some(j.clone());
            Ok(())
        }
        fn clear(&mut self) -> Result<(), String> {
            if self.fail_clear {
                return Err("injected journal clear".into());
            }
            self.journal = None;
            Ok(())
        }
    }
    #[test]
    fn cleanup_readback_failure_retains_durable_authority_and_never_removes_foreign_rows() {
        let mut f = Fake::default();
        let mut j = journal();
        let first = route("0.0.0.0");
        let second = route("128.0.0.0");
        let mut foreign = first.clone();
        foreign.interface_luid += 1;
        f.routes.push(foreign.clone());
        install_routes(&mut f, &mut j, &[first, second], || Ok(())).unwrap();
        f.fail_read_at = Some(f.reads + 2); // Exact read succeeds; delete readback fails.
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        assert_eq!(j.entries.len(), 2);
        assert_eq!(f.journal.as_ref().unwrap().entries.len(), 2);
        assert!(!complete_route_set(&mut f, &j));
        cleanup_routes(&mut f, &mut j).unwrap();
        assert_eq!(f.routes, vec![foreign]);
        assert!(f.journal.is_none());
    }
    #[test]
    fn cleanup_save_failure_can_resume_from_persisted_journal_without_duplicate_delete() {
        let mut f = Fake::default();
        let mut j = journal();
        install_routes(
            &mut f,
            &mut j,
            &[route("0.0.0.0"), route("128.0.0.0")],
            || Ok(()),
        )
        .unwrap();
        f.fail_save_at = Some(f.saves + 1);
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        let mut recovered = f.journal.clone().unwrap(); // Simulate restart: forget volatile progress.
        assert_eq!(recovered.entries.len(), 2);
        assert_eq!(f.deletes, 1);
        cleanup_routes(&mut f, &mut recovered).unwrap();
        assert_eq!(f.deletes, 2);
        assert!(f.routes.is_empty() && f.journal.is_none());
    }
    #[test]
    fn failed_journal_clear_is_not_success_or_permission_to_publish() {
        let mut f = Fake {
            fail_clear: true,
            ..Fake::default()
        };
        let mut j = journal();
        install_routes(&mut f, &mut j, &[route("0.0.0.0")], || Ok(())).unwrap();
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        assert!(f.routes.is_empty());
        assert!(f.journal.is_some());
        assert!(!complete_route_set(&mut f, &j));
        f.fail_clear = false;
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.journal.is_none());
    }
    #[test]
    fn successful_create_retains_live_ownership_when_readback_fails() {
        let mut f = Fake {
            fail_read_at: Some(2),
            ..Fake::default()
        };
        let mut j = journal();
        let r = route("0.0.0.0");
        assert!(install_routes(&mut f, &mut j, &[r], || Ok(())).is_err());
        assert_eq!(f.creates, 1);
        // Only this retained invocation knows Create succeeded. A crash intent
        // on disk is still unconfirmed until it has been durably saved.
        cleanup_routes(&mut f, &mut j).unwrap();
        assert_eq!(f.deletes, 1);
        assert!(f.routes.is_empty() && f.journal.is_none());
    }
    #[test]
    fn failed_confirmation_save_cannot_discard_a_route_on_unconfirmed_delete() {
        let mut f = Fake {
            fail_save_at: Some(2),
            delete_noop: true,
            ..Fake::default()
        };
        let mut j = journal();
        assert!(install_routes(&mut f, &mut j, &[route("0.0.0.0")], || Ok(())).is_err());
        assert_eq!(j.entries.len(), 1);
        assert!(cleanup_routes(&mut f, &mut j)
            .unwrap_err()
            .starts_with("ROUTE_CLEANUP_UNCONFIRMED"));
        assert_eq!(j.entries.len(), 1);
        assert!(f.journal.is_some());
        f.delete_noop = false;
        cleanup_routes(&mut f, &mut j).unwrap();
        // Reconnect is possible only after exact cleanup has been confirmed.
        install_routes(&mut f, &mut j, &[route("0.0.0.0")], || Ok(())).unwrap();
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.routes.is_empty() && f.journal.is_none());
    }
    #[test]
    fn summary_queries_actual_routes_and_does_not_confuse_journal_with_truth() {
        let mut fake = Fake::default();
        let owned = route("0.0.0.0");
        let journal = RouteJournal {
            version: 1,
            owner_pid: std::process::id(),
            entries: vec![RouteEntry {
                route: owned.clone(),
                applied: true,
            }],
        };
        assert_eq!(route_journal_status(&mut fake, &journal), "missing");
        fake.routes.push(owned);
        assert_eq!(route_journal_status(&mut fake, &journal), "confirmed");
        fake.routes[0].metric += 1;
        assert_eq!(route_journal_status(&mut fake, &journal), "changed");
        assert_eq!(fake.deletes, 0);
    }
    fn route(ip: &str) -> OwnedRoute {
        OwnedRoute {
            destination: ip.into(),
            prefix: 1,
            next_hop: "0.0.0.0".into(),
            interface_index: 14,
            interface_luid: 14000,
            metric: 6,
            protocol: 3,
        }
    }
    fn journal() -> RouteJournal {
        RouteJournal {
            version: 1,
            owner_pid: 1,
            entries: vec![],
        }
    }
    #[test]
    fn original_adapter_identity_never_borrows_a_new_luid_alias_or_index() {
        let owned = route("0.0.0.0");
        let same = (
            owned.interface_index,
            owned.interface_luid,
            TUN_INTERFACE_NAME.into(),
        );
        assert!(validate_route_interface(&owned, Some(same.clone())).unwrap());
        assert!(!validate_route_interface(&owned, None).unwrap());
        for different in [
            (same.0 + 1, same.1, same.2.clone()),
            (same.0, same.1 + 1, same.2),
            (
                owned.interface_index,
                owned.interface_luid,
                "Foreign".into(),
            ),
        ] {
            assert!(validate_route_interface(&owned, Some(different)).is_err());
        }
    }
    #[test]
    fn publication_requires_up_adapter_and_all_four_actual_confirmed_routes() {
        require_interface_up(1).unwrap();
        for status in [0, 2, 3, 4, 5, 6, 7] {
            assert!(require_interface_up(status).is_err());
        }
        let mut fake = Fake::default();
        let mut journal = journal();
        assert!(!complete_route_set(&mut fake, &journal));
        let mut routes = vec![
            route("0.0.0.0"),
            route("128.0.0.0"),
            route("::"),
            route("8000::"),
        ];
        for r in routes.iter_mut().skip(2) {
            r.next_hop = "::".into();
        }
        install_routes(&mut fake, &mut journal, &routes, || Ok(())).unwrap();
        assert!(complete_route_set(&mut fake, &journal));
        fake.routes[0].metric += 1;
        assert!(!complete_route_set(&mut fake, &journal));
        fake.routes[0].metric -= 1;
        journal.entries[0].applied = false;
        assert!(!complete_route_set(&mut fake, &journal));
        journal.entries[0].applied = true;
        journal.entries[3] = journal.entries[2].clone();
        assert!(!complete_route_set(&mut fake, &journal));
        journal.entries.pop();
        assert!(!complete_route_set(&mut fake, &journal));
    }
    #[test]
    fn cancellation_before_intent_before_create_and_after_confirmation_rolls_back_only_owned_routes(
    ) {
        for cancel_at in 1..=6 {
            let mut fake = Fake::default();
            let mut journal = journal();
            let mut checks = 0;
            let result = install_routes(
                &mut fake,
                &mut journal,
                &[route("0.0.0.0"), route("128.0.0.0")],
                || {
                    checks += 1;
                    if checks == cancel_at {
                        Err("OPERATION_CANCELLED".into())
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.unwrap_err(), "OPERATION_CANCELLED");
            assert!(
                fake.creates
                    <= if cancel_at <= 2 {
                        0
                    } else if cancel_at <= 5 {
                        1
                    } else {
                        2
                    }
            );
            cleanup_routes(&mut fake, &mut journal).unwrap();
            assert_eq!(fake.creates, fake.deletes);
            assert!(fake.routes.is_empty());
            assert!(fake.journal.is_none());
        }
    }
    #[test]
    fn concurrent_native_cancel_retains_lease_through_route_rollback_without_duplicate_start() {
        use std::sync::{atomic::Ordering, Arc, Barrier};
        let state = Arc::new(AppState::default());
        let lease =
            begin_runtime_operation(&state, Duration::ZERO, "connect", Duration::from_secs(30))
                .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let cancel_state = state.clone();
        let cancel_barrier = barrier.clone();
        let cancellation = std::thread::spawn(move || {
            cancel_barrier.wait();
            cancel_state
                .operation_generation
                .fetch_add(1, Ordering::AcqRel);
            cancel_barrier.wait();
        });
        let mut foreign = route("0.0.0.0");
        foreign.interface_luid += 1;
        let mut backend = Fake {
            routes: vec![foreign.clone()],
            ..Fake::default()
        };
        let mut journal = journal();
        let mut checks = 0;
        let result = install_routes(
            &mut backend,
            &mut journal,
            &[route("0.0.0.0"), route("128.0.0.0")],
            || {
                checks += 1;
                if checks == 3 {
                    barrier.wait();
                    barrier.wait();
                }
                lease.check()
            },
        );
        cancellation.join().unwrap();
        assert!(result.unwrap_err().starts_with("OPERATION_CANCELLED"));
        assert!(begin_runtime_operation(
            &state,
            Duration::ZERO,
            "connect",
            Duration::from_secs(30)
        )
        .is_err());
        cleanup_routes(&mut backend, &mut journal).unwrap();
        assert_eq!(backend.routes, vec![foreign]);
        assert_eq!((backend.creates, backend.deletes), (1, 1));
        assert!(state.operation_machine.lock().unwrap().current.is_some());
        drop(lease);
        assert!(begin_runtime_operation(
            &state,
            Duration::ZERO,
            "connect",
            Duration::from_secs(30)
        )
        .is_ok());
    }
    #[test]
    fn version_one_numeric_luid_journals_from_published_076_remain_readable() {
        let mut route = route("0.0.0.0");
        for luid in [14000, (1u64 << 53) + 1, u64::MAX] {
            route.interface_luid = luid;
            let mut legacy = serde_json::to_value(&route).unwrap();
            legacy["interfaceLuid"] = json!(luid);
            let parsed: OwnedRoute =
                serde_json::from_value(legacy).expect("published version1 journal numeric LUID");
            assert_eq!(parsed, route);
            assert!(serde_json::to_value(parsed).unwrap()["interfaceLuid"].is_string());
        }
        for invalid in [
            json!(-1),
            json!(1.5),
            json!(null),
            json!(true),
            json!({}),
            json!("18446744073709551616"),
        ] {
            let mut value = serde_json::to_value(&route).unwrap();
            value["interfaceLuid"] = invalid;
            assert!(serde_json::from_value::<OwnedRoute>(value).is_err());
        }
    }
    #[test]
    fn interface_luid_keeps_full_u64_identity_in_journal_and_ipc() {
        let mut r = route("0.0.0.0");
        r.interface_luid = u64::MAX;
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains("\"18446744073709551615\""));
        assert_eq!(serde_json::from_str::<OwnedRoute>(&text).unwrap(), r);
    }
    #[test]
    fn successful_exact_restore_100_cycles_no_foreign_routes_deleted() {
        let mut f = Fake::default();
        let mut foreign = route("0.0.0.0");
        foreign.interface_luid = 15000;
        f.routes.push(foreign.clone());
        for _ in 0..100 {
            let mut j = journal();
            install_routes(
                &mut f,
                &mut j,
                &[route("0.0.0.0"), route("128.0.0.0")],
                || Ok(()),
            )
            .unwrap();
            cleanup_routes(&mut f, &mut j).unwrap();
            assert_eq!(f.routes, vec![foreign.clone()]);
        }
        assert_eq!(f.creates, 200);
        assert_eq!(f.deletes, 200);
    }
    #[test]
    fn preexisting_and_changed_routes_never_removed() {
        let mut f = Fake::default();
        let r = route("0.0.0.0");
        f.routes.push(r.clone());
        let mut j = journal();
        assert!(install_routes(&mut f, &mut j, std::slice::from_ref(&r), || Ok(())).is_err());
        assert_eq!(f.deletes, 0);
        f.routes.clear();
        install_routes(&mut f, &mut j, &[r], || Ok(())).unwrap();
        f.routes[0].metric = 99;
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        assert_eq!(f.deletes, 0);
        assert!(f.journal.is_some());
    }
    #[test]
    fn partial_failure_rollback_and_delete_retry() {
        let mut f = Fake {
            fail_create: Some(2),
            ..Fake::default()
        };
        let mut j = journal();
        assert!(install_routes(
            &mut f,
            &mut j,
            &[route("0.0.0.0"), route("128.0.0.0")],
            || Ok(())
        )
        .is_err());
        f.fail_delete = true;
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        assert_eq!(j.entries.len(), 1);
        f.fail_delete = false;
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.routes.is_empty());
    }
    #[test]
    fn journal_failure_before_mutation_and_uncertain_crash_intent() {
        let mut f = Fake {
            fail_save: true,
            ..Fake::default()
        };
        let mut j = journal();
        assert!(install_routes(&mut f, &mut j, &[route("0.0.0.0")], || Ok(())).is_err());
        assert_eq!(f.creates, 0);
        f.fail_save = false;
        f.routes.push(route("0.0.0.0"));
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        assert_eq!(f.deletes, 0);
        let mut invalid = route("8.8.8.8");
        invalid.prefix = 32;
        assert!(!valid_owned_route(&invalid));
    }
}
