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
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
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

fn same_owned_route(expected: &OwnedRoute, current: &OwnedRoute) -> bool {
    // Windows ifIndex can change. LUID and every route ownership field must
    // still match; an index alone never grants permission to delete a route.
    current.interface_index > 0
        && expected.interface_luid == current.interface_luid
        && expected.destination == current.destination
        && expected.prefix == current.prefix
        && expected.next_hop == current.next_hop
        && expected.metric == current.metric
        && expected.protocol == current.protocol
}

fn validate_owned_interface(
    expected_luid: u64,
    actual_luid: u64,
    alias: &str,
) -> Result<(), String> {
    if expected_luid == 0 || expected_luid != actual_luid || alias != TUN_INTERFACE_NAME {
        return Err("ROUTE_INTERFACE_CHANGED: cleanup отказался от другого адаптера.".into());
    }
    Ok(())
}

fn cleanup_routes(
    backend: &mut impl RouteBackend,
    journal: &mut RouteJournal,
) -> Result<(), String> {
    for index in (0..journal.entries.len()).rev() {
        let entry = &journal.entries[index];
        match backend.read(&entry.route)? {
            None => {},
            Some(current) if same_owned_route(&entry.route, &current) && entry.applied => {
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
) -> Result<(), String> {
    for route in routes {
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
        if let Err(error) = backend.create(route) {
            // Failed Create does not confer ownership, even if another writer won the race.
            journal.entries.pop();
            backend.save(journal)?;
            return Err(error);
        }
        // Create succeeded in this live process. Keep that proof for rollback
        // even if the following read fails; the durable intent stays unowned
        // until readback and save both succeed.
        journal.entries.last_mut().expect("route intent").applied = true;
        if !backend
            .read(route)?
            .as_ref()
            .is_some_and(|current| same_owned_route(route, current))
        {
            return Err("ROUTE_CREATE_UNCONFIRMED: запись не совпала с запросом.".into());
        }
        if let Err(error) = backend.save(journal) {
            // This process knows Create succeeded; after a crash an intent alone is not proof.
            if backend
                .read(route)?
                .as_ref()
                .is_some_and(|current| same_owned_route(route, current))
                && backend.delete(route).is_ok()
                && matches!(backend.read(route), Ok(None))
            {
                // An acknowledged delete alone is not proof of absence.
                journal.entries.pop();
                let _ = backend.save(journal);
            }
            return Err(error);
        }
    }
    Ok(())
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
    fn verify_owned_interface(luid: u64) -> Result<(), String> {
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        let status = unsafe { GetIfEntry2(&mut row) };
        if status == ERROR_FILE_NOT_FOUND {
            // Absence does not authorize deletion by a recycled old ifIndex.
            // The route reader must independently confirm absence by LUID.
            return Ok(());
        }
        if status != 0 {
            return Err(format!("ROUTE_INTERFACE_UNAVAILABLE: Win32 {status}."));
        }
        let end = row
            .Alias
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(row.Alias.len());
        validate_owned_interface(
            luid,
            unsafe { row.InterfaceLuid.Value },
            &String::from_utf16_lossy(&row.Alias[..end]),
        )
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
        Ok(index)
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
        // LUID is authoritative. Never fall back to a possibly recycled index.
        value.InterfaceIndex = 0;
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
    pub(super) fn load(backend: &WindowsRoutes) -> Result<Option<RouteJournal>, String> {
        let Some(encrypted) = crate::compat_storage::read_state_file(&backend.path, 32768)
            .map_err(|error| format!("ROUTE_JOURNAL_READ_FAILED: original preserved: {error}"))?
        else {
            return Ok(None);
        };
        let text = decrypt_access_key(&encrypted)?;
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
        // Lookup by the stored LUID, never by a stale/recycled index.
        for entry in &journal.entries {
            verify_owned_interface(entry.route.interface_luid)?;
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
        let index = wait_for_tun_interface(interface_name)?;
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
        if let Err(error) = install_routes(&mut backend, &mut journal, &routes) {
            return Err(match cleanup_routes(&mut backend, &mut journal) {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; rollback: {cleanup}"),
            });
        }
        Ok(())
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
    #[test]
    fn route_journal_reader_refuses_linked_journal_without_trusting_it() {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-route-reader-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let original = root.join("original.dpapi");
        let linked = root.join("owned-tun-routes-v1.dpapi");
        let journal = RouteJournal {
            version: 1,
            owner_pid: std::process::id(),
            entries: vec![],
        };
        let encrypted = encrypt_access_key(&serde_json::to_string(&journal).unwrap()).unwrap();
        fs::write(&original, &encrypted).unwrap();
        fs::hard_link(&original, &linked).unwrap();
        let result = load(&WindowsRoutes {
            path: linked.clone(),
        });
        let preserved = fs::read_to_string(&original).unwrap();
        fs::remove_file(linked).unwrap();
        fs::remove_file(original).unwrap();
        fs::remove_dir(root).unwrap();
        assert!(
            result.is_err(),
            "linked recovery journal must be refused, not trusted or absent"
        );
        assert_eq!(preserved, encrypted);
    }
    #[test]
    fn route_journal_missing_locked_corrupt_and_oversize_remain_distinct() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = std::env::temp_dir().join(format!(
            "vkarmani-route-errors-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let backend = WindowsRoutes {
            path: root.join("owned-tun-routes-v1.dpapi"),
        };
        assert!(load(&backend).unwrap().is_none());
        let journal = RouteJournal {
            version: 1,
            owner_pid: std::process::id(),
            entries: vec![],
        };
        let encrypted = encrypt_access_key(&serde_json::to_string(&journal).unwrap()).unwrap();
        fs::write(&backend.path, &encrypted).unwrap();
        assert_eq!(load(&backend).unwrap().unwrap().version, 1);
        let locked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&backend.path)
            .unwrap();
        let error = load(&backend).unwrap_err();
        drop(locked);
        assert!(error.starts_with("ROUTE_JOURNAL_READ_FAILED"));
        assert_eq!(fs::read_to_string(&backend.path).unwrap(), encrypted);
        for invalid in [String::new(), "not-dpapi".into(), "x".repeat(32769)] {
            fs::write(&backend.path, &invalid).unwrap();
            assert!(load(&backend).is_err());
            assert_eq!(fs::read_to_string(&backend.path).unwrap(), invalid);
        }
        fs::remove_file(backend.path).unwrap();
        fs::remove_dir(root).unwrap();
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
fn route_journal_status(backend: &mut impl RouteBackend, journal: &RouteJournal) -> &'static str {
    if journal.entries.iter().any(|entry| !entry.applied) {
        return "unconfirmed";
    }
    for entry in &journal.entries {
        match backend.read(&entry.route) {
            Ok(Some(route)) if same_owned_route(&entry.route, &route) => {}
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
        match windows::backend(app).and_then(|backend| windows::load(&backend)) {
            Ok(None) => ("none".into(), vec![]),
            Ok(Some(journal)) => {
                let mut query = match windows::backend(app) {
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
        fail_read_on: Option<usize>,
        saves: usize,
        fail_save_on: Option<usize>,
        delete_ack_without_removal: bool,
    }
    impl RouteBackend for Fake {
        fn read(&mut self, route: &OwnedRoute) -> Result<Option<OwnedRoute>, String> {
            self.reads += 1;
            if self.fail_read_on == Some(self.reads) {
                return Err("injected read".into());
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
            if !self.delete_ack_without_removal {
                // IP Helper selects a route by LUID/prefix/next hop, not by
                // the transient interface index, metric or protocol.
                self.routes.retain(|x| {
                    x.destination != r.destination
                        || x.prefix != r.prefix
                        || x.next_hop != r.next_hop
                        || x.interface_luid != r.interface_luid
                });
            }
            Ok(())
        }
        fn save(&mut self, j: &RouteJournal) -> Result<(), String> {
            self.saves += 1;
            if self.fail_save || self.fail_save_on == Some(self.saves) {
                return Err("injected disk".into());
            }
            self.journal = Some(j.clone());
            Ok(())
        }
        fn clear(&mut self) -> Result<(), String> {
            self.journal = None;
            Ok(())
        }
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
    fn interface_luid_keeps_full_u64_identity_in_journal_and_ipc() {
        let mut r = route("0.0.0.0");
        r.interface_luid = u64::MAX;
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains("\"18446744073709551615\""));
        assert_eq!(serde_json::from_str::<OwnedRoute>(&text).unwrap(), r);
    }
    #[test]
    fn successful_create_remains_owned_when_first_readback_fails() {
        let mut f = Fake {
            fail_read_on: Some(2),
            ..Fake::default()
        };
        let mut j = journal();
        assert_eq!(
            install_routes(&mut f, &mut j, &[route("0.0.0.0")]).unwrap_err(),
            "injected read"
        );
        assert_eq!(f.routes.len(), 1);
        // The durable intent alone is still insufficient after a crash. The
        // live process, however, observed Create succeed and can roll it back.
        assert!(!f.journal.as_ref().unwrap().entries[0].applied);
        f.routes[0].metric = 99;
        assert!(cleanup_routes(&mut f, &mut j)
            .unwrap_err()
            .starts_with("ROUTE_OWNER_CHANGED"));
        assert_eq!(f.deletes, 0);
        f.routes[0].metric = 6;
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.routes.is_empty());
        assert!(f.journal.is_none());
    }
    #[test]
    fn rollback_delete_ack_requires_absence_before_discarding_ownership() {
        let mut f = Fake {
            fail_save_on: Some(2),
            delete_ack_without_removal: true,
            ..Fake::default()
        };
        let mut j = journal();
        assert!(install_routes(&mut f, &mut j, &[route("0.0.0.0")]).is_err());
        assert_eq!(f.routes.len(), 1);
        assert_eq!(j.entries.len(), 1);
        assert!(j.entries[0].applied);
        assert!(cleanup_routes(&mut f, &mut j)
            .unwrap_err()
            .starts_with("ROUTE_CLEANUP_UNCONFIRMED"));
        assert_eq!(j.entries.len(), 1);
        f.delete_ack_without_removal = false;
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.routes.is_empty());
        assert!(f.journal.is_none());
    }
    #[test]
    fn failed_persistence_with_confirmed_delete_can_discard_live_ownership() {
        let mut f = Fake {
            fail_save_on: Some(2),
            ..Fake::default()
        };
        let mut j = journal();
        assert_eq!(
            install_routes(&mut f, &mut j, &[route("0.0.0.0")]).unwrap_err(),
            "injected disk"
        );
        assert!(f.routes.is_empty());
        assert!(j.entries.is_empty());
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.journal.is_none());
    }
    #[test]
    fn same_luid_route_survives_index_change_but_not_changed_owner_fields() {
        let mut f = Fake::default();
        let mut j = journal();
        install_routes(&mut f, &mut j, &[route("0.0.0.0")]).unwrap();
        f.routes[0].interface_index = 99;
        assert_eq!(route_journal_status(&mut f, &j), "confirmed");
        f.routes[0].protocol = 99;
        assert!(cleanup_routes(&mut f, &mut j)
            .unwrap_err()
            .starts_with("ROUTE_OWNER_CHANGED"));
        assert_eq!(f.deletes, 0);
        f.routes[0].protocol = 3;
        cleanup_routes(&mut f, &mut j).unwrap();
        assert!(f.routes.is_empty());
        assert!(f.journal.is_none());
    }
    #[test]
    fn route_owner_requires_every_tuple_field_and_exact_interface_alias() {
        let expected = route("0.0.0.0");
        assert!(validate_owned_interface(
            expected.interface_luid,
            expected.interface_luid,
            TUN_INTERFACE_NAME
        )
        .is_ok());
        assert!(validate_owned_interface(
            expected.interface_luid,
            expected.interface_luid + 1,
            TUN_INTERFACE_NAME
        )
        .is_err());
        assert!(validate_owned_interface(
            expected.interface_luid,
            expected.interface_luid,
            "foreign-tun"
        )
        .is_err());
        for mutate in [
            |r: &mut OwnedRoute| r.interface_luid += 1,
            |r: &mut OwnedRoute| r.metric += 1,
            |r: &mut OwnedRoute| r.protocol += 1,
            |r: &mut OwnedRoute| r.prefix += 1,
            |r: &mut OwnedRoute| r.destination = "128.0.0.0".into(),
            |r: &mut OwnedRoute| r.next_hop = "192.0.2.1".into(),
            |r: &mut OwnedRoute| r.interface_index = 0,
        ] {
            let mut changed = expected.clone();
            mutate(&mut changed);
            assert!(!same_owned_route(&expected, &changed));
        }
    }
    #[test]
    fn successful_exact_restore_100_cycles_no_foreign_routes_deleted() {
        let mut f = Fake::default();
        let mut foreign = route("0.0.0.0");
        foreign.interface_luid = 15000;
        f.routes.push(foreign.clone());
        for _ in 0..100 {
            let mut j = journal();
            install_routes(&mut f, &mut j, &[route("0.0.0.0"), route("128.0.0.0")]).unwrap();
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
        assert!(install_routes(&mut f, &mut j, std::slice::from_ref(&r)).is_err());
        assert_eq!(f.deletes, 0);
        f.routes.clear();
        install_routes(&mut f, &mut j, &[r]).unwrap();
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
        assert!(install_routes(&mut f, &mut j, &[route("0.0.0.0"), route("128.0.0.0")]).is_err());
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
        assert!(install_routes(&mut f, &mut j, &[route("0.0.0.0")]).is_err());
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
