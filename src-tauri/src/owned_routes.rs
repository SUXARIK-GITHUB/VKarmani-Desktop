use super::*;

fn tun_destinations(interface: TunInterfacePlan) -> &'static [&'static str] {
    if interface.ipv6_guard {
        &["0.0.0.0", "128.0.0.0", "::", "8000::"]
    } else {
        &["0.0.0.0", "128.0.0.0"]
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_created_at: Option<u64>,
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
        if let Err(error) = backend.save(journal) {
            // No Create was called for this entry. Do not invent ownership or
            // attempt another journal write as though network rollback failed.
            journal.entries.pop();
            return Err(error);
        } // Durable intent before the OS mutation.
        if let Err(error) = backend.create(route) {
            // Failed Create does not confer ownership, even if another writer won the race.
            journal.entries.pop();
            if let Err(save) = backend.save(journal) {
                return Err(format!("{error}; journal: {save}"));
            }
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
        backend.save(journal)?;
    }
    Ok(())
}

fn install_routes_with_rollback(
    backend: &mut impl RouteBackend,
    journal: &mut RouteJournal,
    routes: &[OwnedRoute],
) -> Result<(), String> {
    let Err(error) = install_routes(backend, journal, routes) else {
        return Ok(());
    };
    // Install never deletes its own successful creates. Every such live proof
    // stays applied=true until this one, verified rollback boundary handles it.
    let created = journal.entries.iter().filter(|entry| entry.applied).count();
    if created == 0 {
        return Err(format!(
            "ROUTE_SETUP_NOT_STARTED: новые управляемые маршруты этой операцией не создавались; {error}"
        ));
    }
    Err(match cleanup_routes(backend, journal) {
        Ok(()) => format!("ROUTE_SETUP_ROLLED_BACK: создано {created}, отсутствие собственных маршрутов подтверждено; {error}"),
        Err(cleanup) if journal.entries.is_empty() => format!("ROUTE_ROLLBACK_JOURNAL_PENDING: создано {created}, отсутствие собственных маршрутов подтверждено; журнал не завершён: {cleanup}; причина: {error}"),
        Err(cleanup) => format!("ROUTE_ROLLBACK_UNCONFIRMED: создано {created}, восстановление не подтверждено; {error}; rollback: {cleanup}"),
    })
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use windows_sys::{
        core::GUID,
        Win32::{
            Devices::{
                DeviceAndDriverInstallation::{
                    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
                    SetupDiGetDevicePropertyW, SetupDiOpenDevRegKey, DICS_FLAG_GLOBAL,
                    DIGCF_PRESENT, DIREG_DRV, HDEVINFO, SP_DEVINFO_DATA,
                },
                Properties::{DEVPROPKEY, DEVPROP_TYPE_STRING},
            },
            Foundation::{
                CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
                ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
                WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
            },
            NetworkManagement::{
                IpHelper::*,
                Ndis::{MediaConnectStateConnected, MediaConnectStateDisconnected, NET_LUID_LH},
            },
            Networking::WinSock::*,
            System::{
                Com::CLSIDFromString,
                Registry::{RegCloseKey, RegGetValueW, KEY_QUERY_VALUE, RRF_RT_REG_SZ},
                Threading::{
                    GetCurrentProcess, GetProcessTimes, OpenProcess, WaitForSingleObject,
                    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
                },
            },
        },
    };

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn win32_error() -> u32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
    }

    fn process_created_at(handle: HANDLE) -> Result<u64, u32> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
        if unsafe { GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) } == 0
        {
            return Err(win32_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    #[derive(Debug, PartialEq, Eq)]
    enum OwnerObservation {
        Exited,
        Running,
        IdentityOnly(u64),
        Unknown(&'static str, u32),
    }

    fn open_owner(pid: u32, access: u32) -> Result<ProcessHandle, u32> {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return Err(win32_error());
        }
        Ok(ProcessHandle(handle))
    }

    fn owner_observation(pid: u32, created_at: Option<u64>) -> OwnerObservation {
        let handle = match open_owner(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
        {
            Ok(handle) => handle,
            Err(ERROR_INVALID_PARAMETER) => return OwnerObservation::Exited,
            Err(ERROR_ACCESS_DENIED) if created_at.is_some() => {
                // Query-only can prove PID reuse, never that the same owner exited.
                return match open_owner(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
                    Ok(handle) => match process_created_at(handle.0) {
                        Ok(created) => OwnerObservation::IdentityOnly(created),
                        Err(code) => OwnerObservation::Unknown("GetProcessTimes", code),
                    },
                    Err(ERROR_INVALID_PARAMETER) => OwnerObservation::Exited,
                    Err(code) => OwnerObservation::Unknown("OpenProcess(query)", code),
                };
            }
            Err(code) => return OwnerObservation::Unknown("OpenProcess", code),
        };
        match unsafe { WaitForSingleObject(handle.0, 0) } {
            WAIT_OBJECT_0 => OwnerObservation::Exited,
            WAIT_TIMEOUT if created_at.is_some() => match process_created_at(handle.0) {
                Ok(created) if Some(created) != created_at => {
                    OwnerObservation::IdentityOnly(created)
                }
                Ok(_) => OwnerObservation::Running,
                Err(code) => OwnerObservation::Unknown("GetProcessTimes", code),
            },
            WAIT_TIMEOUT => OwnerObservation::Running,
            WAIT_FAILED => OwnerObservation::Unknown("WaitForSingleObject", win32_error()),
            code => OwnerObservation::Unknown("WaitForSingleObject result", code),
        }
    }

    fn verify_previous_owner(
        journal: &RouteJournal,
        observe: impl FnOnce(u32, Option<u64>) -> OwnerObservation,
    ) -> Result<(), String> {
        let pid = journal.owner_pid;
        let current_pid = std::process::id();
        if pid == 0 || journal.owner_created_at == Some(0) {
            return Err("ROUTE_OWNER_UNKNOWN: invalid journal owner identity".into());
        }
        if pid == current_pid {
            let recorded = journal.owner_created_at.ok_or(
                "ROUTE_OWNER_UNKNOWN: current PID matches a legacy journal without creation identity",
            )?;
            let current = process_created_at(unsafe { GetCurrentProcess() })
                .map_err(|code| format!("ROUTE_OWNER_UNKNOWN: GetProcessTimes: Win32 {code}"))?;
            // The retained current identity proves either this owner or a
            // later process that reused its PID. Route validation still follows.
            if recorded <= current {
                return Ok(());
            }
            return Err(
                "ROUTE_OWNER_UNKNOWN: journal owner is newer than the current process".into(),
            );
        }
        let details =
            format!(
            "ownerPID={pid}, currentPID={current_pid}, ownerCreatedAt={:?}, entries={}, LUID={:?}",
            journal.owner_created_at,
            journal.entries.len(),
            journal.entries.first().map(|entry| entry.route.interface_luid),
        );
        match observe(pid, journal.owner_created_at) {
            OwnerObservation::Exited => Ok(()),
            OwnerObservation::IdentityOnly(created)
                if journal.owner_created_at.is_some_and(|owner| owner != created) =>
            {
                Ok(())
            }
            OwnerObservation::Running => Err(format!(
                "ROUTE_OWNER_ACTIVE: предыдущий owner process ещё активен. {details}"
            )),
            OwnerObservation::IdentityOnly(_) => Err(format!(
                "ROUTE_OWNER_UNKNOWN: невозможно проверить завершение предыдущего process. Win32 {ERROR_ACCESS_DENIED}; {details}"
            )),
            OwnerObservation::Unknown(operation, code) => Err(format!(
                "ROUTE_OWNER_UNKNOWN: невозможно проверить предыдущий process. {operation}: Win32 {code}; {details}"
            )),
        }
    }

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
    #[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
    pub(crate) struct AdapterIdentity {
        guid: [u8; 16],
        #[serde(with = "luid_text")]
        luid: u64,
        kind: u32,
        description: String,
    }

    impl AdapterIdentity {
        fn is_wintun(&self) -> bool {
            self.guid != [0; 16]
                && self.luid != 0
                && self.kind == IF_TYPE_PROP_VIRTUAL
                && self.description.to_ascii_lowercase().contains("wintun")
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct AdapterReceipt {
        version: u8,
        identity: AdapterIdentity,
        pid: u32,
        created_at: u64,
    }

    struct AdapterObservation {
        identity: AdapterIdentity,
        index: u32,
        media: i32,
    }

    impl AdapterObservation {
        fn details(&self) -> String {
            let AdapterIdentity {
                guid, luid, kind, ..
            } = self.identity;
            let guid: String = guid.iter().map(|byte| format!("{byte:02x}")).collect();
            format!(
                "alias={TUN_INTERFACE_NAME}, GUID={guid}, LUID={luid}, index={}, ifType={kind}, Wintun={}, media={}",
                self.index, self.identity.is_wintun(), self.media,
            )
        }
    }

    fn wide_field(field: &[u16]) -> String {
        let end = field
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(field.len());
        String::from_utf16_lossy(&field[..end])
    }

    fn guid_bytes(raw: GUID) -> [u8; 16] {
        let mut guid = [0; 16];
        guid[..4].copy_from_slice(&raw.data1.to_be_bytes());
        guid[4..6].copy_from_slice(&raw.data2.to_be_bytes());
        guid[6..8].copy_from_slice(&raw.data3.to_be_bytes());
        guid[8..].copy_from_slice(&raw.data4);
        guid
    }

    struct DeviceList(HDEVINFO);

    impl Drop for DeviceList {
        fn drop(&mut self) {
            unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }

    fn named_wintun_device() -> Result<Option<[u8; 16]>, String> {
        // WintunOpenAdapter uses this device property, which Windows adapter
        // renames do not update. Reading it via SetupAPI has no Wintun side effects.
        const NET_CLASS: GUID = GUID::from_u128(0x4d36e972_e325_11ce_bfc1_08002be10318);
        const WINTUN_NAME: DEVPROPKEY = DEVPROPKEY {
            fmtid: GUID::from_u128(0x3361c968_2f2e_4660_b47e_699cdc4c32b9),
            pid: 3,
        };
        let fail = |api, code| format!("TUN_INTERFACE_OWNER_UNKNOWN: {api}: Win32 {code}");
        let mut matched = None;
        // The pinned Wintun uses SWD on supported Windows, ROOT on Windows 7.
        for enumerator in [r"SWD\Wintun", r"ROOT\Wintun"] {
            let enumerator: Vec<u16> = enumerator.encode_utf16().chain(Some(0)).collect();
            let devices = unsafe {
                SetupDiGetClassDevsW(&NET_CLASS, enumerator.as_ptr(), null_mut(), DIGCF_PRESENT)
            };
            if devices == INVALID_HANDLE_VALUE as HDEVINFO {
                return Err(fail("SetupDiGetClassDevsW", win32_error()));
            }
            let devices = DeviceList(devices);
            let mut ended = false;
            for index in 0..8192 {
                let mut node: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
                node.cbSize = std::mem::size_of_val(&node) as u32;
                if unsafe { SetupDiEnumDeviceInfo(devices.0, index, &mut node) } == 0 {
                    let code = win32_error();
                    if code != ERROR_NO_MORE_ITEMS {
                        return Err(fail("SetupDiEnumDeviceInfo", code));
                    }
                    ended = true;
                    break;
                }
                let mut name = [0u16; 256];
                let mut kind = 0;
                if unsafe {
                    SetupDiGetDevicePropertyW(
                        devices.0,
                        &node,
                        &WINTUN_NAME,
                        &mut kind,
                        name.as_mut_ptr().cast(),
                        std::mem::size_of_val(&name) as u32,
                        null_mut(),
                        0,
                    )
                } == 0
                {
                    let code = win32_error();
                    if code == ERROR_NOT_FOUND {
                        continue; // WintunOpenAdapter also skips nodes without its name.
                    }
                    return Err(fail("SetupDiGetDevicePropertyW", code));
                }
                if kind != DEVPROP_TYPE_STRING
                    || !wide_field(&name).eq_ignore_ascii_case(TUN_INTERFACE_NAME)
                {
                    continue;
                }
                if matched.is_some() {
                    return Err("TUN_INTERFACE_OWNER_UNKNOWN: duplicate Wintun device name".into());
                }
                let key = unsafe {
                    SetupDiOpenDevRegKey(
                        devices.0,
                        &node,
                        DICS_FLAG_GLOBAL,
                        0,
                        DIREG_DRV,
                        KEY_QUERY_VALUE,
                    )
                };
                if key == INVALID_HANDLE_VALUE {
                    return Err(fail("SetupDiOpenDevRegKey", win32_error()));
                }
                let value: Vec<u16> = "NetCfgInstanceId".encode_utf16().chain(Some(0)).collect();
                let mut guid = [0u16; 40];
                let mut bytes = std::mem::size_of_val(&guid) as u32;
                let status = unsafe {
                    RegGetValueW(
                        key,
                        null(),
                        value.as_ptr(),
                        RRF_RT_REG_SZ,
                        null_mut(),
                        guid.as_mut_ptr().cast(),
                        &mut bytes,
                    )
                };
                unsafe { RegCloseKey(key) };
                if status != 0 {
                    return Err(fail("NetCfgInstanceId", status));
                }
                let mut parsed = GUID::from_u128(0);
                if bytes != 78
                    || guid[38] != 0
                    || unsafe { CLSIDFromString(guid.as_ptr(), &mut parsed) } != 0
                {
                    return Err(
                        "TUN_INTERFACE_OWNER_UNKNOWN: invalid Wintun NetCfgInstanceId".into(),
                    );
                }
                matched = Some(guid_bytes(parsed));
            }
            if !ended {
                return Err("TUN_INTERFACE_TABLE_LIMIT: Wintun devices".into());
            }
        }
        Ok(matched)
    }

    fn verify_wintun_name(
        current: Option<&AdapterObservation>,
        named_device: Option<[u8; 16]>,
    ) -> Result<(), String> {
        match (current, named_device) {
            (None, None) => Ok(()),
            (Some(current), Some(guid)) if current.identity.guid == guid => Ok(()),
            (Some(current), _) => Err(format!(
                "TUN_INTERFACE_OWNER_UNKNOWN: Windows alias and Wintun name identify different devices; {}",
                current.details()
            )),
            (None, Some(_)) => Err("TUN_INTERFACE_OWNER_UNKNOWN: Wintun device exists without matching Windows alias".into()),
        }
    }

    fn observe_adapter() -> Result<Option<AdapterObservation>, String> {
        let mut table = null_mut();
        let status = unsafe { GetIfTable2(&mut table) };
        if status != 0 || table.is_null() {
            return Err(format!("TUN_INTERFACE_TABLE_UNAVAILABLE: Win32 {status}"));
        }
        let count = unsafe { (*table).NumEntries } as usize;
        let result: Result<_, String> = if count <= 8192 {
            let rows = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
                    count,
                )
            };
            let mut matches = rows
                .iter()
                .filter(|row| wide_field(&row.Alias).eq_ignore_ascii_case(TUN_INTERFACE_NAME));
            let first = matches.next();
            if matches.next().is_some() {
                Err("TUN_INTERFACE_OWNER_UNKNOWN: multiple matching aliases".into())
            } else {
                Ok(first.map(|row| AdapterObservation {
                    identity: AdapterIdentity {
                        guid: guid_bytes(row.InterfaceGuid),
                        luid: unsafe { row.InterfaceLuid.Value },
                        kind: row.Type,
                        description: wide_field(&row.Description),
                    },
                    index: row.InterfaceIndex,
                    media: row.MediaConnectState,
                }))
            }
        } else {
            Err("TUN_INTERFACE_TABLE_LIMIT".into())
        };
        unsafe { FreeMibTable(table.cast()) };
        let observed = result?;
        verify_wintun_name(observed.as_ref(), named_wintun_device()?)?;
        Ok(observed)
    }

    fn load_adapter_receipt(path: &Path) -> Result<Option<AdapterReceipt>, String> {
        let invalid = || {
            "TUN_INTERFACE_OWNER_UNKNOWN: protected adapter receipt invalid; original preserved"
                .to_string()
        };
        let Some(cipher) = crate::compat_storage::read_state_file(path, 4096).map_err(|error| {
            format!("TUN_INTERFACE_OWNER_UNKNOWN: protected adapter receipt unreadable: {error}")
        })?
        else {
            return Ok(None);
        };
        let text = decrypt_access_key(&cipher).map_err(|_| invalid())?;
        let receipt: AdapterReceipt = serde_json::from_str(&text).map_err(|_| invalid())?;
        if receipt.version != 1
            || receipt.pid == 0
            || receipt.created_at == 0
            || !receipt.identity.is_wintun()
        {
            return Err(invalid());
        }
        Ok(Some(receipt))
    }

    fn save_adapter_receipt(path: &Path, receipt: &AdapterReceipt) -> Result<(), String> {
        let text = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        atomic_write_text(path, &encrypt_access_key(&text)?, "TUN adapter receipt")
    }

    fn admit_idle_adapter(
        current: &AdapterObservation,
        receipt: Option<&AdapterReceipt>,
        observe_owner: impl FnOnce(u32, Option<u64>) -> OwnerObservation,
    ) -> Result<(), String> {
        if current.media == MediaConnectStateConnected {
            return Err(format!(
                "TUN_INTERFACE_ACTIVE: active link; {}",
                current.details()
            ));
        }
        let Some(receipt) = receipt.filter(|receipt| receipt.identity == current.identity) else {
            return Err(format!(
                "TUN_INTERFACE_OWNER_UNKNOWN: no matching protected receipt; {}",
                current.details()
            ));
        };
        if current.media != MediaConnectStateDisconnected
            || current.index == 0
            || !current.identity.is_wintun()
        {
            return Err(format!(
                "TUN_INTERFACE_OWNER_UNKNOWN: link state or identity unconfirmed; {}",
                current.details()
            ));
        }
        let owner = format!(
            "ownerPID={}, ownerCreatedAt={}",
            receipt.pid, receipt.created_at
        );
        match observe_owner(receipt.pid, Some(receipt.created_at)) {
            OwnerObservation::Exited => Ok(()),
            OwnerObservation::IdentityOnly(created) if created != receipt.created_at => Ok(()),
            OwnerObservation::Running => Err(format!(
                "TUN_INTERFACE_ACTIVE: recorded Xray is alive; {owner}, {}",
                current.details()
            )),
            other => Err(format!(
                "TUN_INTERFACE_OWNER_UNKNOWN: Xray exit unconfirmed ({other:?}); {owner}, {}",
                current.details()
            )),
        }
    }

    fn expected_idle_address(row: &MIB_UNICASTIPADDRESS_ROW) -> bool {
        let ip = match unsafe { row.Address.si_family } {
            AF_INET => IpAddr::from(unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() }),
            AF_INET6 => {
                let ip = std::net::Ipv6Addr::from(unsafe { row.Address.Ipv6.sin6_addr.u.Byte });
                if ip.segments()[0] & 0xffc0 == 0xfe80
                    && row.PrefixOrigin == IpPrefixOriginWellKnown
                {
                    return true;
                }
                IpAddr::from(ip)
            }
            _ => return false,
        };
        [TUN_GATEWAY_IPV4, TUN_GATEWAY_IPV6].iter().any(|gateway| {
            let (host, prefix) = gateway.split_once('/').expect("fixed TUN prefix");
            host.parse::<IpAddr>() == Ok(ip) && prefix.parse::<u8>() == Ok(row.OnLinkPrefixLength)
        })
    }

    // Xray may replace interface addresses and DNS at start and flush routes at
    // close. Even an owned interface may have externally configured state.
    fn verify_idle_configuration(current: &AdapterObservation) -> Result<(), String> {
        let luid = current.identity.luid;
        let mut addresses = null_mut();
        let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut addresses) };
        if status != 0 || addresses.is_null() {
            return Err(format!(
                "TUN_INTERFACE_ADDRESS_UNCONFIRMED: Win32 {status}; {}",
                current.details()
            ));
        }
        let count = unsafe { (*addresses).NumEntries } as usize;
        let addresses_ok = count <= 65536
            && unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!((*addresses).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
                    count,
                )
            }
            .iter()
            .filter(|row| unsafe { row.InterfaceLuid.Value == luid })
            .all(|row| row.InterfaceIndex == current.index && expected_idle_address(row));
        unsafe { FreeMibTable(addresses.cast()) };

        let mut routes = null_mut();
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut routes) };
        if status != 0 || routes.is_null() {
            return Err(format!(
                "TUN_INTERFACE_ROUTES_UNCONFIRMED: Win32 {status}; {}",
                current.details()
            ));
        }
        let count = unsafe { (*routes).NumEntries } as usize;
        let routes_ok = count <= 65536
            && unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!((*routes).Table).cast::<MIB_IPFORWARD_ROW2>(),
                    count,
                )
            }
            .iter()
            .filter(|row| unsafe { row.InterfaceLuid.Value == luid })
            .all(|row| row.InterfaceIndex == current.index && row.Protocol == MIB_IPPROTO_LOCAL);
        unsafe { FreeMibTable(routes.cast()) };

        let dns = read_interface_dns(current.index, luid).map_err(|error| {
            format!(
                "TUN_INTERFACE_DNS_UNCONFIRMED: {error}; {}",
                current.details()
            )
        })?;
        let dns_ok = dns.is_empty() || dns == TUN_DNS;
        if !addresses_ok || !routes_ok || !dns_ok {
            return Err(format!(
                "TUN_INTERFACE_CONFIGURATION_UNKNOWN: expected addresses={addresses_ok}, local routes only={routes_ok}, expected DNS={dns_ok}; {}",
                current.details(),
            ));
        }
        Ok(())
    }

    fn adapter_receipt_path(app: &AppHandle) -> Result<PathBuf, String> {
        Ok(runtime_output_dir(app)?.join("owned-tun-adapter-v1.dpapi"))
    }

    pub(super) fn prepare_adapter(app: &AppHandle) -> Result<Option<AdapterIdentity>, String> {
        let receipt = load_adapter_receipt(&adapter_receipt_path(app)?)?;
        let Some(current) = observe_adapter()? else {
            return Ok(None);
        };
        admit_idle_adapter(&current, receipt.as_ref(), owner_observation)?;
        verify_idle_configuration(&current)?;
        let after = observe_adapter()?
            .ok_or("TUN_INTERFACE_OWNER_UNKNOWN: alias disappeared during admission")?;
        if after.identity != current.identity
            || after.index != current.index
            || after.media != current.media
        {
            return Err(format!(
                "TUN_INTERFACE_OWNER_UNKNOWN: adapter changed during admission; {}",
                after.details()
            ));
        }
        let _ = append_runtime_event(
            app,
            &format!("TUN_INTERFACE_REUSE_ADMITTED: {}", current.details()),
        );
        Ok(Some(current.identity))
    }

    fn verify_started_adapter(
        current: &AdapterObservation,
        expected: Option<&AdapterIdentity>,
        link: (u32, u64),
    ) -> Result<(), String> {
        if (current.index, current.identity.luid) != link
            || current.media != MediaConnectStateConnected
            || !current.identity.is_wintun()
            || expected.is_some_and(|expected| *expected != current.identity)
        {
            return Err(format!(
                "TUN_INTERFACE_GENERATION_UNCONFIRMED: {}",
                current.details()
            ));
        }
        Ok(())
    }

    pub(super) fn confirm_started_adapter(
        expected: Option<&AdapterIdentity>,
        link: (u32, u64),
    ) -> Result<AdapterIdentity, String> {
        let current =
            observe_adapter()?.ok_or("TUN_INTERFACE_GENERATION_UNCONFIRMED: alias missing")?;
        verify_started_adapter(&current, expected, link)?;
        Ok(current.identity)
    }

    pub(super) fn record_adapter(
        app: &AppHandle,
        identity: AdapterIdentity,
        child: &mut Child,
    ) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle;
        let created_at = process_created_at(child.as_raw_handle()).map_err(|code| {
            format!("TUN_INTERFACE_OWNER_UNKNOWN: GetProcessTimes: Win32 {code}")
        })?;
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(
                "TUN_INTERFACE_OWNER_EXITED: Xray exited before recording the adapter".into(),
            );
        }
        save_adapter_receipt(
            &adapter_receipt_path(app)?,
            &AdapterReceipt {
                version: 1,
                identity,
                pid: child.id(),
                created_at,
            },
        )?;
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(
                "TUN_INTERFACE_OWNER_EXITED: Xray exited before publishing the runtime".into(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn adapter_fixture() -> (AdapterObservation, AdapterReceipt) {
        let identity = || AdapterIdentity {
            guid: [42; 16],
            luid: 88,
            kind: IF_TYPE_PROP_VIRTUAL,
            description: "Wintun Userspace Tunnel".into(),
        };
        (
            AdapterObservation {
                identity: identity(),
                index: 12,
                media: MediaConnectStateDisconnected,
            },
            AdapterReceipt {
                version: 1,
                identity: identity(),
                pid: 44,
                created_at: 200,
            },
        )
    }

    #[test]
    fn tun_adapter_reuse_requires_matching_receipt_idle_link_and_ended_generation() {
        let (mut current, receipt) = adapter_fixture();
        let no_process_lookup = |_, _| panic!("no owner lookup expected");
        assert!(admit_idle_adapter(&current, None, no_process_lookup)
            .unwrap_err()
            .starts_with("TUN_INTERFACE_OWNER_UNKNOWN"));
        current.index = 13; // The index is not persistent, unlike the journal's identity check.
        for owner in [
            OwnerObservation::Exited,
            OwnerObservation::IdentityOnly(201),
        ] {
            admit_idle_adapter(&current, Some(&receipt), |pid, created| {
                assert_eq!((pid, created), (44, Some(200)));
                owner
            })
            .unwrap();
        }
        for (owner, code) in [
            (OwnerObservation::Running, "TUN_INTERFACE_ACTIVE"),
            (
                OwnerObservation::IdentityOnly(200),
                "TUN_INTERFACE_OWNER_UNKNOWN",
            ),
            (
                OwnerObservation::Unknown("OpenProcess", 5),
                "TUN_INTERFACE_OWNER_UNKNOWN",
            ),
        ] {
            assert!(admit_idle_adapter(&current, Some(&receipt), |_, _| owner)
                .unwrap_err()
                .starts_with(code));
        }
        current.media = MediaConnectStateConnected;
        assert!(
            admit_idle_adapter(&current, Some(&receipt), no_process_lookup)
                .unwrap_err()
                .starts_with("TUN_INTERFACE_ACTIVE")
        );
        current.media = 0; // Unknown is not proof of inactivity.
        assert!(admit_idle_adapter(&current, Some(&receipt), no_process_lookup).is_err());
        current.media = MediaConnectStateDisconnected;
        current.identity.luid += 1;
        assert!(admit_idle_adapter(&current, Some(&receipt), no_process_lookup).is_err());
        current.identity.luid -= 1;
        current.identity.guid[0] ^= 1;
        assert!(admit_idle_adapter(&current, Some(&receipt), no_process_lookup).is_err());
        current.identity.guid[0] ^= 1;
        current.identity.description = "other adapter".into();
        assert!(admit_idle_adapter(&current, Some(&receipt), no_process_lookup).is_err());
    }

    #[test]
    fn tun_adapter_admission_checks_the_name_used_by_wintun() {
        let (current, _) = adapter_fixture();
        verify_wintun_name(None, None).unwrap();
        verify_wintun_name(Some(&current), Some(current.identity.guid)).unwrap();
        assert!(verify_wintun_name(None, Some(current.identity.guid)).is_err());
        assert!(verify_wintun_name(Some(&current), None).is_err());
        assert!(verify_wintun_name(Some(&current), Some([5; 16])).is_err());
    }

    #[test]
    fn tun_adapter_pnp_enumeration_is_read_only() {
        // Query the same device property as WintunOpenAdapter without loading
        // wintun.dll or triggering its orphan cleanup. No adapter is required.
        named_wintun_device().unwrap();
    }

    #[test]
    fn tun_adapter_runtime_must_use_the_observed_generation() {
        let (mut current, receipt) = adapter_fixture();
        let link = (current.index, current.identity.luid);
        assert!(verify_started_adapter(&current, Some(&receipt.identity), link).is_err());
        current.media = MediaConnectStateConnected;
        verify_started_adapter(&current, None, link).unwrap();
        verify_started_adapter(&current, Some(&receipt.identity), link).unwrap();
        assert!(verify_started_adapter(&current, Some(&receipt.identity), (0, link.1)).is_err());
        current.identity.guid[1] ^= 1;
        assert!(verify_started_adapter(&current, Some(&receipt.identity), link).is_err());
        current.identity.kind = 6;
        assert!(verify_started_adapter(&current, None, link).is_err());
    }

    #[test]
    fn tun_adapter_receipt_round_trips_with_dpapi_and_preserves_invalid_state() {
        let (_, mut receipt) = adapter_fixture();
        let root = std::env::temp_dir().join(format!(
            "vkarmani-adapter-receipt-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("owned-tun-adapter-v1.dpapi");
        assert!(load_adapter_receipt(&path).unwrap().is_none());
        for created_at in [200, 201] {
            receipt.created_at = created_at;
            save_adapter_receipt(&path, &receipt).unwrap();
            let loaded = load_adapter_receipt(&path).unwrap().unwrap();
            assert_eq!(loaded.identity, receipt.identity);
            assert_eq!(loaded.pid, receipt.pid);
            assert_eq!(loaded.created_at, created_at);
        }
        receipt.pid = 0;
        save_adapter_receipt(&path, &receipt).unwrap();
        let invalid = fs::read(&path).unwrap();
        assert!(load_adapter_receipt(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), invalid);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn tun_adapter_reuse_protects_manually_configured_addresses() {
        let mut row = unsafe { std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>() };
        row.Address = address("172.19.0.1").unwrap();
        row.OnLinkPrefixLength = 32;
        assert!(expected_idle_address(&row));
        row.OnLinkPrefixLength = 24;
        assert!(!expected_idle_address(&row));
        row.Address = address("192.0.2.1").unwrap();
        assert!(!expected_idle_address(&row));
        row.Address = address("fdfe:dcba:9876::1").unwrap();
        row.OnLinkPrefixLength = 128;
        assert!(expected_idle_address(&row));
        row.Address = address("fe80::1").unwrap();
        row.PrefixOrigin = IpPrefixOriginManual;
        assert!(!expected_idle_address(&row));
        row.PrefixOrigin = IpPrefixOriginWellKnown;
        assert!(expected_idle_address(&row));
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

    fn interface_row(luid: u64, family: u16) -> (u32, MIB_IPINTERFACE_ROW) {
        let mut row = unsafe { std::mem::zeroed::<MIB_IPINTERFACE_ROW>() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        (unsafe { GetIpInterfaceEntry(&mut row) }, row)
    }

    fn ready_address(
        row: &MIB_UNICASTIPADDRESS_ROW,
        status: u32,
        index: u32,
        luid: u64,
        prefix: u8,
    ) -> bool {
        status == 0
            && row.InterfaceIndex == index
            && unsafe { row.InterfaceLuid.Value == luid }
            && row.OnLinkPrefixLength == prefix
            && row.DadState == IpDadStatePreferred
            && row.SkipAsSource == 0
    }

    #[test]
    fn tun_address_must_be_preferred_and_belong_to_the_current_luid() {
        let mut row = unsafe { std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>() };
        row.InterfaceIndex = 42;
        row.InterfaceLuid = NET_LUID_LH { Value: 99 };
        row.OnLinkPrefixLength = 32;
        row.DadState = IpDadStatePreferred;
        assert!(ready_address(&row, 0, 42, 99, 32));
        assert!(!ready_address(&row, ERROR_NOT_FOUND, 42, 99, 32));
        assert!(!ready_address(&row, 0, 42, 100, 32));
        assert!(!ready_address(&row, 0, 43, 99, 32));
        assert!(!ready_address(&row, 0, 42, 99, 128));
        for state in [
            IpDadStateTentative,
            IpDadStateDuplicate,
            IpDadStateDeprecated,
        ] {
            row.DadState = state;
            assert!(!ready_address(&row, 0, 42, 99, 32));
        }
        row.DadState = IpDadStatePreferred;
        row.SkipAsSource = 1;
        assert!(!ready_address(&row, 0, 42, 99, 32));
    }

    pub(super) fn ready(alias: &str, interface: TunInterfacePlan) -> Result<(u32, u64), String> {
        let index = find_index(alias)?;
        let (luid, actual) = interface_identity(index)?;
        validate_owned_interface(luid, luid, &actual)?;
        let mut link = unsafe { std::mem::zeroed::<MIB_IF_ROW2>() };
        link.InterfaceLuid = NET_LUID_LH { Value: luid };
        let status = unsafe { GetIfEntry2(&mut link) };
        if status != 0 || link.InterfaceIndex != index || link.OperStatus != 1 {
            return Err(format!(
                "TUN_INTERFACE_NOT_READY: index={index}, LUID={luid}, Win32 {status}"
            ));
        }
        for (gateway, prefix) in interface.gateways().iter().zip([32, 128]) {
            let ip = gateway.split_once('/').expect("fixed TUN prefix").0;
            let mut row = unsafe { std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>() };
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = NET_LUID_LH { Value: luid };
            row.Address = address(ip)?;
            let family = unsafe { row.Address.si_family };
            let status = unsafe { GetUnicastIpAddressEntry(&mut row) };
            if !ready_address(&row, status, index, luid, prefix) {
                return Err(format!("TUN_ADDRESS_NOT_READY: index={index}, LUID={luid}, family={family}, dad={}, Win32 {status}", row.DadState));
            }
            let (status, ip_interface) = interface_row(luid, family);
            if status != 0 || ip_interface.InterfaceIndex != index || ip_interface.NlMtu != TUN_MTU
            {
                return Err(format!("TUN_MTU_UNCONFIRMED: index={index}, LUID={luid}, family={family}, MTU={}, Win32 {status}", ip_interface.NlMtu));
            }
        }
        if !interface.ipv6_guard && interface_row(luid, AF_INET6).0 != ERROR_NOT_FOUND {
            return Err(
                "TUN_IPV6_GUARD_REQUIRED: live adapter did not confirm disabled IPv6".into(),
            );
        }
        if interface.adapter_dns && read_interface_dns(index, luid)? != interface.dns() {
            return Err(format!("TUN_DNS_UNCONFIRMED: index={index}, LUID={luid}"));
        }
        Ok((index, luid))
    }

    pub(super) fn confirm_effective_routes(
        index: u32,
        luid: u64,
        interface: TunInterfacePlan,
    ) -> Result<(), String> {
        // Read-only lookups in each journal-owned half. No socket or traffic.
        let samples = ["24.0.0.1", "198.51.100.1", "2001:db8::1", "a000::1"];
        for sample in &samples[..tun_destinations(interface).len()] {
            let mut row = unsafe { std::mem::zeroed::<MIB_IPFORWARD_ROW2>() };
            let mut source = unsafe { std::mem::zeroed::<SOCKADDR_INET>() };
            let destination = address(sample)?;
            let mut selected_index = 0;
            let selection = unsafe {
                GetBestInterfaceEx(
                    (&destination as *const SOCKADDR_INET).cast(),
                    &mut selected_index,
                )
            };
            let status = unsafe {
                GetBestRoute2(
                    null(),
                    index,
                    null(),
                    &destination,
                    0,
                    &mut row,
                    &mut source,
                )
            };
            if status != 0
                || selection != 0
                || selected_index != index
                || row.InterfaceIndex != index
                || unsafe { row.InterfaceLuid.Value != luid }
                || row.DestinationPrefix.PrefixLength != 1
                || row.Metric != 6
            {
                return Err(format!("TUN_EFFECTIVE_ROUTE_UNCONFIRMED: index={index}, LUID={luid}, Win32 {status}/{selection}, selectedIndex={selected_index}, routeMetric={}", row.Metric));
            }
        }
        Ok(())
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
        pub(super) path: PathBuf,
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
        verify_previous_owner(&journal, owner_observation)?;
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
    pub(super) fn configure(
        app: &AppHandle,
        interface_name: &str,
        interface: TunInterfacePlan,
        expected_adapter: Option<&AdapterIdentity>,
    ) -> Result<AdapterIdentity, String> {
        cleanup(app)?;
        let deadline = Instant::now() + Duration::from_secs(6);
        let (index, luid) = loop {
            match ready(interface_name, interface) {
                Ok(value) => break value,
                Err(error) if Instant::now() >= deadline => return Err(error),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let adapter = confirm_started_adapter(expected_adapter, (index, luid))?;
        let routes = tun_destinations(interface)
            .iter()
            .map(|&ip| OwnedRoute {
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
            owner_created_at: Some(
                process_created_at(unsafe { GetCurrentProcess() }).map_err(|code| {
                    format!("ROUTE_OWNER_UNKNOWN: GetProcessTimes: Win32 {code}")
                })?,
            ),
            entries: Vec::new(),
        };
        install_routes_with_rollback(&mut backend, &mut journal, &routes)?;
        Ok(adapter)
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
    fn journal_refuses_a_live_other_process_then_allows_confirmed_exited_owner() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "vkarmani-journal-owner-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let mut command = Command::new(system_program("powershell").unwrap());
        command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::In.ReadToEnd() | Out-Null",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        hide_child_console(&mut command);
        let mut child = OwnedXrayProcess::attach(command.spawn().unwrap()).unwrap();
        let mut backend = WindowsRoutes {
            path: root.join("owned-tun-routes-v1.dpapi"),
        };
        backend
            .save(&RouteJournal {
                version: 1,
                owner_pid: child.id(),
                owner_created_at: None,
                entries: vec![],
            })
            .unwrap();
        let original = fs::read(&backend.path).unwrap();
        assert!(load(&backend)
            .unwrap_err()
            .starts_with("ROUTE_OWNER_ACTIVE:"));
        assert_eq!(fs::read(&backend.path).unwrap(), original);
        let handle = open_owner(child.id(), PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let actual = process_created_at(handle.0).unwrap();
        let mut journal = RouteJournal {
            version: 1,
            owner_pid: child.id(),
            owner_created_at: Some(actual),
            entries: vec![],
        };
        backend.save(&journal).unwrap();
        assert!(load(&backend)
            .unwrap_err()
            .starts_with("ROUTE_OWNER_ACTIVE:"));
        // Exercise real OpenProcess/GetProcessTimes on a live process that
        // stands in for a recycled PID. Do not open or mutate any routes.
        journal.owner_created_at = Some(actual - 1);
        backend.save(&journal).unwrap();
        assert_eq!(
            load(&backend).unwrap().unwrap().owner_created_at,
            Some(actual - 1)
        );
        drop(handle);
        assert!(terminate_child_with_timeout(&mut child, Duration::from_secs(2)).is_some());
        assert!(load(&backend).unwrap().unwrap().entries.is_empty());
        drop(child);
        backend.clear().unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn uncertain_previous_owner_preserves_the_journal_and_distinguishes_win32_errors() {
        let mut journal = RouteJournal {
            version: 1,
            owner_pid: u32::MAX,
            owner_created_at: Some(42),
            entries: vec![],
        };
        for code in [5, 32, 33] {
            let error = verify_previous_owner(&journal, |_, _| {
                OwnerObservation::Unknown("OpenProcess", code)
            })
            .unwrap_err();
            assert!(error.starts_with("ROUTE_OWNER_UNKNOWN:"));
            assert!(error.contains(&format!("Win32 {code}")));
        }
        assert!(
            verify_previous_owner(&journal, |_, _| OwnerObservation::IdentityOnly(42)).is_err()
        );
        assert!(verify_previous_owner(&journal, |_, _| OwnerObservation::IdentityOnly(43)).is_ok());
        assert!(verify_previous_owner(&journal, |_, _| OwnerObservation::Exited).is_ok());
        journal.owner_created_at = None;
        assert!(
            verify_previous_owner(&journal, |_, _| OwnerObservation::IdentityOnly(43)).is_err()
        );
        journal.owner_pid = 0;
        assert!(verify_previous_owner(&journal, |_, _| panic!("invalid PID was queried")).is_err());
    }

    #[test]
    fn a_current_pid_with_no_generation_does_not_prove_legacy_route_ownership() {
        let actual = process_created_at(unsafe { GetCurrentProcess() }).unwrap();
        let mut journal = RouteJournal {
            version: 1,
            owner_pid: std::process::id(),
            owner_created_at: None,
            entries: vec![],
        };
        let unexpected = |_, _| panic!("current process uses its retained identity");
        assert!(verify_previous_owner(&journal, unexpected)
            .unwrap_err()
            .starts_with("ROUTE_OWNER_UNKNOWN:"));
        journal.owner_created_at = Some(actual);
        assert!(verify_previous_owner(&journal, unexpected).is_ok());
        journal.owner_created_at = Some(actual - 1);
        assert!(verify_previous_owner(&journal, unexpected).is_ok());
        journal.owner_created_at = Some(actual + 1);
        assert!(verify_previous_owner(&journal, unexpected).is_err());
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
            owner_created_at: None,
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
            owner_created_at: Some(process_created_at(unsafe { GetCurrentProcess() }).unwrap()),
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
pub(crate) fn configure_tun_routes(
    app: &AppHandle,
    interface_name: &str,
    interface: TunInterfacePlan,
    expected_adapter: Option<&AdapterIdentity>,
) -> Result<AdapterIdentity, String> {
    #[cfg(target_os = "windows")]
    {
        windows::configure(app, interface_name, interface, expected_adapter)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (app, interface_name, interface, expected_adapter);
        Err("Windows TUN only".into())
    }
}

#[cfg(target_os = "windows")]
pub(crate) use windows::AdapterIdentity;
#[cfg(not(target_os = "windows"))]
pub(crate) struct AdapterIdentity;

pub(crate) fn prepare_owned_tun_adapter(
    app: &AppHandle,
) -> Result<Option<AdapterIdentity>, String> {
    #[cfg(target_os = "windows")]
    {
        windows::prepare_adapter(app)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        Err("Windows TUN only".into())
    }
}

pub(crate) fn record_owned_tun_adapter(
    app: &AppHandle,
    adapter: AdapterIdentity,
    child: &mut OwnedXrayProcess,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows::record_adapter(app, adapter, child)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (app, adapter, child);
        Err("Windows TUN only".into())
    }
}

pub(crate) fn confirm_tun_routes_ready(
    app: &AppHandle,
    interface: TunInterfacePlan,
    adapter: &AdapterIdentity,
) -> Result<(), String> {
    let (status, routes) = owned_route_summary(app);
    #[cfg(target_os = "windows")]
    if status == "confirmed" && complete_tun_route_set(&routes, interface) {
        let (index, luid) = windows::ready(TUN_INTERFACE_NAME, interface)?;
        if routes[0].interface_luid != luid {
            return Err("TUN_ROUTES_NOT_READY: adapter generation changed".into());
        }
        windows::confirm_started_adapter(Some(adapter), (index, luid))?;
        windows::confirm_effective_routes(index, luid, interface)?;
        let _ = append_runtime_event(app, &format!(
            "TUN_LINK_CONFIRMED: index={index}, LUID={luid}, Preferred, MTU={TUN_MTU}, ownedRoutes={}, adapterDnsConfigured={}",
            routes.len(), interface.adapter_dns,
        ));
        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    let _ = (interface, adapter);
    Err(format!(
        "TUN_ROUTES_NOT_READY: ownership={status}, recorded={}",
        routes.len()
    ))
}

fn complete_tun_route_set(routes: &[OwnedRoute], interface: TunInterfacePlan) -> bool {
    let destinations = tun_destinations(interface);
    routes.len() == destinations.len()
        && routes.iter().all(|route| {
            valid_owned_route(route) && route.interface_luid == routes[0].interface_luid
        })
        && destinations
            .iter()
            .all(|destination| routes.iter().any(|route| route.destination == *destination))
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
        fail_save_from: Option<usize>,
        clears: usize,
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
            if self.fail_save
                || self.fail_save_on == Some(self.saves)
                || self.fail_save_from.is_some_and(|from| self.saves >= from)
            {
                return Err("injected disk".into());
            }
            self.journal = Some(j.clone());
            Ok(())
        }
        fn clear(&mut self) -> Result<(), String> {
            self.clears += 1;
            self.journal = None;
            Ok(())
        }
    }
    #[cfg(windows)]
    struct DiskFake {
        state: Fake,
        disk: windows::WindowsRoutes,
    }
    #[cfg(windows)]
    impl RouteBackend for DiskFake {
        fn read(&mut self, r: &OwnedRoute) -> Result<Option<OwnedRoute>, String> {
            self.state.read(r)
        }
        fn create(&mut self, r: &OwnedRoute) -> Result<(), String> {
            self.state.create(r)
        }
        fn delete(&mut self, r: &OwnedRoute) -> Result<(), String> {
            self.state.delete(r)
        }
        fn save(&mut self, j: &RouteJournal) -> Result<(), String> {
            let prior = self.state.journal.clone();
            self.state.save(j)?;
            if let Err(error) = self.disk.save(j) {
                self.state.journal = prior;
                return Err(error);
            }
            Ok(())
        }
        fn clear(&mut self) -> Result<(), String> {
            self.disk.clear()?;
            self.state.clear()
        }
    }
    #[cfg(windows)]
    fn disk_fixture() -> (PathBuf, DiskFake, Vec<File>) {
        let root = std::env::temp_dir().join(format!(
            "vkarmani-route-transaction-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        let guards = lock_runtime_parent_paths(&root.join("synthetic-config.json")).unwrap();
        let backend = DiskFake {
            state: Fake::default(),
            disk: windows::WindowsRoutes {
                path: root.join("owned-tun-routes-v1.dpapi"),
            },
        };
        (root, backend, guards)
    }
    #[cfg(windows)]
    fn disk_snapshot(backend: &DiskFake) -> RouteJournal {
        let cipher = crate::compat_storage::read_state_file(&backend.disk.path, 32768)
            .unwrap()
            .unwrap();
        let plain = decrypt_access_key(&cipher).unwrap();
        assert!(!cipher.contains("interfaceLuid"));
        serde_json::from_str(&plain).unwrap()
    }
    #[cfg(windows)]
    fn finish_disk(root: PathBuf, mut backend: DiskFake, guards: Vec<File>) {
        backend.disk.clear().unwrap();
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            0,
            "no partial temporary files"
        );
        drop(guards);
        fs::remove_dir(root).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn disk_journal_first_and_repeated_save_keep_dpapi_with_live_runtime_pins() {
        let (root, mut backend, guards) = disk_fixture();
        let mut j = journal();
        backend.save(&j).unwrap();
        assert!(disk_snapshot(&backend).entries.is_empty());
        j.entries.push(RouteEntry {
            route: route("0.0.0.0"),
            applied: false,
        });
        backend.save(&j).unwrap();
        assert!(!disk_snapshot(&backend).entries[0].applied);
        j.entries[0].applied = true;
        backend.save(&j).unwrap();
        assert!(disk_snapshot(&backend).entries[0].applied);
        finish_disk(root, backend, guards);
    }
    #[test]
    #[cfg(windows)]
    fn restarted_backend_recovers_applied_entries_without_touching_foreign_routes() {
        let (root, mut backend, guards) = disk_fixture();
        let mut foreign = route("0.0.0.0");
        foreign.interface_luid += 1;
        backend.state.routes.push(foreign.clone());
        let mut j = journal();
        install_routes_with_rollback(
            &mut backend,
            &mut j,
            &[route("0.0.0.0"), route("128.0.0.0")],
        )
        .unwrap();
        let mut recovered = disk_snapshot(&backend);
        assert!(recovered.entries.iter().all(|e| e.applied));
        backend.state = Fake {
            routes: backend.state.routes.clone(),
            ..Fake::default()
        };
        cleanup_routes(&mut backend, &mut recovered).unwrap();
        assert_eq!(backend.state.routes, vec![foreign]);
        assert_eq!(backend.state.deletes, 2);
        assert!(!backend.disk.path.exists());
        finish_disk(root, backend, guards);
    }
    #[test]
    #[cfg(windows)]
    fn locked_initial_intent_changes_no_routes_and_preserves_last_good_cipher() {
        use std::os::windows::fs::OpenOptionsExt;
        let (root, mut backend, guards) = disk_fixture();
        let mut j = journal();
        backend.save(&j).unwrap();
        let original = fs::read(&backend.disk.path).unwrap();
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&backend.disk.path)
            .unwrap();
        backend.state.saves = 0;
        let started = Instant::now();
        let error =
            install_routes_with_rollback(&mut backend, &mut j, &[route("0.0.0.0")]).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(error.starts_with("ROUTE_SETUP_NOT_STARTED:"));
        assert!(error.contains("новые управляемые маршруты этой операцией не создавались"));
        // Windows reports 32 for a pinned parent and may report 5 for an open
        // target; the writer verifies the latter conflict before bounded retry.
        assert!(
            error.contains("os error 32") || error.contains("os error 5"),
            "actual held-file result: {error}"
        );
        assert!(!error.contains("rollback:"));
        assert_eq!(
            (
                backend.state.creates,
                backend.state.deletes,
                backend.state.saves,
                backend.state.clears
            ),
            (0, 0, 1, 0)
        );
        assert!(j.entries.is_empty());
        drop(blocker);
        assert_eq!(fs::read(&backend.disk.path).unwrap(), original);
        install_routes_with_rollback(&mut backend, &mut j, &[route("0.0.0.0")]).unwrap();
        cleanup_routes(&mut backend, &mut j).unwrap();
        finish_disk(root, backend, guards);
    }
    #[test]
    #[cfg(windows)]
    fn partial_create_and_rollback_save_failure_recover_from_durable_journal() {
        for fail_rollback_save in [false, true] {
            let (root, mut backend, guards) = disk_fixture();
            let mut foreign = route("0.0.0.0");
            foreign.interface_luid += 1;
            backend.state.routes.push(foreign.clone());
            backend.state.fail_create = Some(2);
            backend.state.fail_save_from = fail_rollback_save.then_some(5);
            let mut j = journal();
            let error = install_routes_with_rollback(
                &mut backend,
                &mut j,
                &[route("0.0.0.0"), route("128.0.0.0")],
            )
            .unwrap_err();
            assert_eq!(backend.state.routes, vec![foreign.clone()]);
            assert_eq!(backend.state.deletes, 1);
            if fail_rollback_save {
                assert!(error.starts_with("ROUTE_ROLLBACK_JOURNAL_PENDING:"));
                let mut recovered = disk_snapshot(&backend);
                assert_eq!(recovered.entries.len(), 1);
                backend.state = Fake {
                    routes: vec![foreign.clone()],
                    ..Fake::default()
                }; // new process/backend state
                cleanup_routes(&mut backend, &mut recovered).unwrap();
                assert_eq!(backend.state.deletes, 0); // removed route is already absent
            } else {
                assert!(error.starts_with("ROUTE_SETUP_ROLLED_BACK:"));
            }
            assert_eq!(backend.state.routes, vec![foreign]);
            assert!(!backend.disk.path.exists());
            finish_disk(root, backend, guards);
        }
    }
    #[test]
    #[cfg(windows)]
    fn confirmation_save_failure_and_failed_delete_retain_proof_for_retry() {
        let (root, mut backend, guards) = disk_fixture();
        backend.state.fail_save_from = Some(2);
        backend.state.fail_delete = true;
        let mut j = journal();
        let error =
            install_routes_with_rollback(&mut backend, &mut j, &[route("0.0.0.0")]).unwrap_err();
        assert!(error.starts_with("ROUTE_ROLLBACK_UNCONFIRMED:"));
        assert!(j.entries[0].applied);
        assert!(!disk_snapshot(&backend).entries[0].applied);
        assert_eq!(backend.state.routes.len(), 1);
        backend.state.fail_delete = false;
        backend.state.fail_save_from = None;
        cleanup_routes(&mut backend, &mut j).unwrap();
        assert!(backend.state.routes.is_empty());
        finish_disk(root, backend, guards);
    }
    #[test]
    #[cfg(windows)]
    fn restarted_unconfirmed_intent_never_authorizes_deleting_matching_route() {
        let (root, mut backend, guards) = disk_fixture();
        let mut j = journal();
        j.entries.push(RouteEntry {
            route: route("0.0.0.0"),
            applied: false,
        });
        backend.save(&j).unwrap();
        let original = fs::read(&backend.disk.path).unwrap();
        let mut recovered = disk_snapshot(&backend);
        backend.state = Fake {
            routes: vec![route("0.0.0.0")],
            ..Fake::default()
        };
        assert!(cleanup_routes(&mut backend, &mut recovered)
            .unwrap_err()
            .starts_with("ROUTE_OWNER_CHANGED:"));
        assert_eq!(backend.state.deletes, 0);
        assert_eq!(fs::read(&backend.disk.path).unwrap(), original);
        finish_disk(root, backend, guards);
    }
    #[test]
    fn summary_queries_actual_routes_and_does_not_confuse_journal_with_truth() {
        let mut fake = Fake::default();
        let owned = route("0.0.0.0");
        let journal = RouteJournal {
            version: 1,
            owner_pid: std::process::id(),
            owner_created_at: None,
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
            next_hop: if ip.contains(':') { "::" } else { "0.0.0.0" }.into(),
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
            owner_created_at: None,
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
            install_routes_with_rollback(&mut f, &mut j, &[route("0.0.0.0")]).unwrap_err(),
            "ROUTE_SETUP_ROLLED_BACK: создано 1, отсутствие собственных маршрутов подтверждено; injected disk"
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
    fn ready_requires_all_four_routes_on_one_interface_generation() {
        let mut routes = ["0.0.0.0", "128.0.0.0", "::", "8000::"].map(route);
        let mut interface = TunInterfacePlan {
            ipv6_guard: true,
            adapter_dns: true,
        };
        assert!(complete_tun_route_set(&routes, interface));
        assert!(!complete_tun_route_set(&routes[..3], interface));
        routes[2].interface_luid += 1;
        assert!(!complete_tun_route_set(&routes, interface));
        routes[2] = routes[3].clone();
        assert!(!complete_tun_route_set(&routes, interface));
        interface.ipv6_guard = false;
        assert!(complete_tun_route_set(&routes[..2], interface));
        assert!(!complete_tun_route_set(&routes, interface));
        routes[0].metric = 7;
        assert!(!complete_tun_route_set(&routes[..2], interface));
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
        assert!(
            j.entries.is_empty(),
            "an unsaved intent is not live ownership"
        );
        f.fail_save = false;
        // A *persisted* pre-Create intent from an interrupted older attempt
        // is a different state from the failed-save case above.
        j.entries.push(RouteEntry {
            route: route("0.0.0.0"),
            applied: false,
        });
        f.save(&j).unwrap();
        f.routes.push(route("0.0.0.0"));
        assert!(cleanup_routes(&mut f, &mut j).is_err());
        assert_eq!(f.deletes, 0);
        let mut invalid = route("8.8.8.8");
        invalid.prefix = 32;
        assert!(!valid_owned_route(&invalid));
    }
}
