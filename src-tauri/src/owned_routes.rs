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
        if backend.read(route)?.as_ref() != Some(route) {
            return Err("ROUTE_CREATE_UNCONFIRMED: запись не совпала с запросом.".into());
        }
        journal.entries.last_mut().expect("route intent").applied = true;
        if let Err(error) = backend.save(journal) {
            // This process knows Create succeeded; after a crash an intent alone is not proof.
            if backend.read(route)?.as_ref() == Some(route) && backend.delete(route).is_ok() {
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
        Foundation::{CloseHandle, ERROR_NOT_FOUND},
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
        if !backend.path.exists() {
            return Ok(None);
        }
        if fs::metadata(&backend.path)
            .map_err(|_| "Route journal metadata".to_string())?
            .len()
            > 32768
        {
            return Err("Route journal too large".into());
        }
        let text = decrypt_access_key(
            &fs::read_to_string(&backend.path).map_err(|_| "Route journal read".to_string())?,
        )?;
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
        // An absent adapter implies absent active routes. A different LUID/alias is never authority.
        for entry in &journal.entries {
            if let Ok((luid, alias)) = interface_identity(entry.route.interface_index) {
                if luid != entry.route.interface_luid || alias != TUN_INTERFACE_NAME {
                    return Err(
                        "ROUTE_INTERFACE_CHANGED: cleanup отказался от другого адаптера.".into(),
                    );
                }
            }
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
    }
    impl RouteBackend for Fake {
        fn read(&mut self, route: &OwnedRoute) -> Result<Option<OwnedRoute>, String> {
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
            self.routes.retain(|x| x != r);
            Ok(())
        }
        fn save(&mut self, j: &RouteJournal) -> Result<(), String> {
            if self.fail_save {
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
