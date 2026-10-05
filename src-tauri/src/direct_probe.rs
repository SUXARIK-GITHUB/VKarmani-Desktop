//! Read-only physical-interface selection and per-socket binding. Never edit routes.
use super::*;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProbePath {
    pub(crate) interface_index: u32,
    pub(crate) source_ip: String,
    pub(crate) destination_ip: String,
    pub(crate) elapsed_micros: u128,
}

fn eligible_physical_interface(
    kind: u32,
    flags: u8,
    operational: i32,
    prefix: u8,
    has_gateway: bool,
) -> bool {
    matches!(kind, 6 | 71) && flags & 1 != 0 && operational == 1 && prefix == 0 && has_gateway
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    struct Winsock;
    impl Drop for Winsock {
        fn drop(&mut self) {
            unsafe {
                WSACleanup();
            }
        }
    }
    struct Socket(SOCKET);
    impl Drop for Socket {
        fn drop(&mut self) {
            unsafe {
                closesocket(self.0);
            }
        }
    }
    fn socket_error(stage: &str) -> String {
        format!("DIRECT_{stage}:{}", unsafe { WSAGetLastError() })
    }
    fn ip(value: &SOCKADDR_INET) -> IpAddr {
        unsafe {
            if value.si_family == AF_INET {
                IpAddr::V4(Ipv4Addr::from(
                    value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ))
            } else {
                IpAddr::V6(Ipv6Addr::from(value.Ipv6.sin6_addr.u.Byte))
            }
        }
    }
    fn destination(value: std::net::SocketAddr) -> SOCKADDR_INET {
        let mut out: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        match value {
            std::net::SocketAddr::V4(addr) => {
                out.Ipv4.sin_family = AF_INET;
                out.Ipv4.sin_port = addr.port().to_be();
                out.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.ip().octets());
            }
            std::net::SocketAddr::V6(addr) => {
                out.Ipv6.sin6_family = AF_INET6;
                out.Ipv6.sin6_port = addr.port().to_be();
                out.Ipv6.sin6_addr.u.Byte = addr.ip().octets();
                out.Ipv6.Anonymous.sin6_scope_id = addr.scope_id();
            }
        }
        out
    }
    fn physical_source(destination: &SOCKADDR_INET) -> Result<(u32, SOCKADDR_INET), String> {
        let family = unsafe { destination.si_family };
        let mut raw = std::ptr::null_mut();
        let status = unsafe { GetIpForwardTable2(family, &mut raw) };
        if status != 0 || raw.is_null() {
            return Err(format!("DIRECT_ROUTE_TABLE:{status}"));
        }
        let table = Table(raw);
        let count = unsafe { (*table.0).NumEntries } as usize;
        if count > 4096 {
            return Err("DIRECT_ROUTE_TABLE_LIMIT".into());
        }
        let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), count) };
        let mut candidates = Vec::new();
        for route in rows {
            let mut interface: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
            interface.InterfaceIndex = route.InterfaceIndex;
            if unsafe { GetIfEntry2(&mut interface) } != 0 {
                continue;
            }
            if !eligible_physical_interface(
                interface.Type,
                interface.InterfaceAndOperStatusFlags._bitfield,
                interface.OperStatus,
                route.DestinationPrefix.PrefixLength,
                !ip(&route.NextHop).is_unspecified(),
            ) {
                continue;
            }
            let mut details: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
            unsafe {
                InitializeIpInterfaceEntry(&mut details);
            }
            details.Family = family;
            details.InterfaceIndex = route.InterfaceIndex;
            if unsafe { GetIpInterfaceEntry(&mut details) } != 0 {
                continue;
            }
            candidates.push((
                u64::from(route.Metric) + u64::from(details.Metric),
                route.InterfaceIndex,
            ));
        }
        candidates.sort_unstable();
        candidates.dedup();
        for (_, index) in candidates {
            let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
            let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
            let status = unsafe {
                GetBestRoute2(
                    std::ptr::null(),
                    index,
                    std::ptr::null(),
                    destination,
                    0,
                    &mut route,
                    &mut source,
                )
            };
            if status == 0 && route.InterfaceIndex == index && !ip(&source).is_unspecified() {
                return Ok((index, source));
            }
        }
        Err("DIRECT_NO_PHYSICAL_ROUTE".into())
    }
    fn dns_servers(index: u32, luid: u64) -> Result<Vec<String>, String> {
        // Aligned OS-owned result buffer, bounded retries if adapters change
        // between calls. No DNS request and no private adapter data persisted.
        let mut size = 15 * 1024u32;
        for _ in 0..3 {
            if size > 1024 * 1024 {
                return Err("NETWORK_ADAPTER_TABLE_LIMIT".into());
            }
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            let raw = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.into(),
                    GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                    std::ptr::null(),
                    raw,
                    &mut size,
                )
            };
            if status == 111 {
                continue;
            }
            if status != 0 {
                return Err(format!("NETWORK_ADAPTER_TABLE:{status}"));
            }
            let mut adapter = raw;
            for _ in 0..512 {
                if adapter.is_null() {
                    break;
                }
                let item = unsafe { &*adapter };
                if unsafe { item.Anonymous1.Anonymous.IfIndex == index && item.Luid.Value == luid }
                {
                    let mut dns = item.FirstDnsServerAddress;
                    let mut result = Vec::new();
                    for _ in 0..16 {
                        if dns.is_null() {
                            return Ok(result);
                        }
                        let address = unsafe { (*dns).Address };
                        if !address.lpSockaddr.is_null() {
                            let family = unsafe { (*address.lpSockaddr).sa_family };
                            let required = if family == AF_INET {
                                std::mem::size_of::<SOCKADDR_IN>()
                            } else if family == AF_INET6 {
                                std::mem::size_of::<SOCKADDR_IN6>()
                            } else {
                                0
                            };
                            if required > 0 && address.iSockaddrLength >= required as i32 {
                                let mut value: SOCKADDR_INET = unsafe { std::mem::zeroed() };
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        address.lpSockaddr.cast::<u8>(),
                                        (&mut value as *mut SOCKADDR_INET).cast::<u8>(),
                                        required,
                                    );
                                }
                                result.push(ip(&value).to_string());
                            }
                        }
                        dns = unsafe { (*dns).Next };
                    }
                    return Err("NETWORK_DNS_TABLE_LIMIT".into());
                }
                adapter = item.Next;
            }
            return Err("NETWORK_ADAPTER_CHANGED".into());
        }
        Err("NETWORK_ADAPTER_TABLE_UNSTABLE".into())
    }
    pub(super) fn binding_snapshot() -> Result<DefaultRouteSnapshot, String> {
        // TEST-NET is only an input to a route lookup. No packet is sent.
        let dest = destination(std::net::SocketAddr::from(([203, 0, 113, 1], 0)));
        let (index, source) = physical_source(&dest)?;
        let mut interface: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        interface.InterfaceIndex = index;
        if unsafe { GetIfEntry2(&mut interface) } != 0
            || !eligible_physical_interface(
                interface.Type,
                interface.InterfaceAndOperStatusFlags._bitfield,
                interface.OperStatus,
                0,
                true,
            )
        {
            return Err("NETWORK_INTERFACE_CHANGED".into());
        }
        let mut address: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        address.Address = source;
        address.InterfaceIndex = index;
        if unsafe { GetUnicastIpAddressEntry(&mut address) } != 0
            || address.DadState != 4
            || address.SkipAsSource != 0
            || unsafe { address.InterfaceLuid.Value != interface.InterfaceLuid.Value }
        {
            return Err("NETWORK_SOURCE_NOT_PREFERRED".into());
        }
        let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        let mut selected_source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        if unsafe {
            GetBestRoute2(
                std::ptr::null(),
                index,
                std::ptr::null(),
                &dest,
                0,
                &mut route,
                &mut selected_source,
            )
        } != 0
            || route.InterfaceIndex != index
            || unsafe { route.InterfaceLuid.Value != interface.InterfaceLuid.Value }
            || ip(&selected_source) != ip(&source)
            || ip(&route.NextHop).is_unspecified()
        {
            return Err("NETWORK_ROUTE_CHANGED".into());
        }
        let len = interface
            .Alias
            .iter()
            .position(|c| *c == 0)
            .ok_or("NETWORK_ALIAS_INVALID")?;
        let alias =
            String::from_utf16(&interface.Alias[..len]).map_err(|_| "NETWORK_ALIAS_INVALID")?;
        let luid = unsafe { interface.InterfaceLuid.Value };
        let dns = dns_servers(index, luid)?;
        Ok(DefaultRouteSnapshot {
            interface_index: index,
            interface_luid: luid,
            interface_alias: alias,
            source_ip: ip(&source).to_string(),
            next_hop: ip(&route.NextHop).to_string(),
            dns_servers: dns,
        })
    }
    fn connect_bound(
        index: u32,
        source: &SOCKADDR_INET,
        dest: &SOCKADDR_INET,
        timeout: Duration,
    ) -> Result<u128, String> {
        let family = unsafe { dest.si_family };
        if index == 0 || ip(source).is_unspecified() || unsafe { source.si_family } != family {
            return Err("DIRECT_INVALID_BINDING".into());
        }
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        if unsafe { WSAStartup(0x202, &mut data) } != 0 {
            return Err("DIRECT_WSA_STARTUP".into());
        }
        let _winsock = Winsock;
        let raw = unsafe {
            WSASocketW(
                family as i32,
                SOCK_STREAM,
                IPPROTO_TCP,
                std::ptr::null(),
                0,
                WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if raw == INVALID_SOCKET {
            return Err(socket_error("SOCKET"));
        }
        let socket = Socket(raw);
        let (level, option, value) = if family == AF_INET {
            (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
        } else {
            (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
        };
        if unsafe { setsockopt(socket.0, level, option, (&value as *const u32).cast(), 4) } != 0 {
            return Err(socket_error("INTERFACE_BIND"));
        }
        let length = if family == AF_INET {
            std::mem::size_of::<SOCKADDR_IN>()
        } else {
            std::mem::size_of::<SOCKADDR_IN6>()
        } as i32;
        if unsafe { bind(socket.0, (source as *const SOCKADDR_INET).cast(), length) } != 0 {
            return Err(socket_error("SOURCE_BIND"));
        }
        let mut enabled = 1;
        if unsafe { ioctlsocket(socket.0, FIONBIO, &mut enabled) } != 0 {
            return Err(socket_error("NONBLOCKING"));
        }
        let started = Instant::now();
        if unsafe { connect(socket.0, (dest as *const SOCKADDR_INET).cast(), length) } != 0 {
            if unsafe { WSAGetLastError() } != WSAEWOULDBLOCK {
                return Err(socket_error("CONNECT"));
            }
            let mut write: FD_SET = unsafe { std::mem::zeroed() };
            write.fd_count = 1;
            write.fd_array[0] = socket.0;
            let mut error = write;
            let deadline = TIMEVAL {
                tv_sec: timeout.as_secs().min(i32::MAX as u64) as i32,
                tv_usec: timeout.subsec_micros() as i32,
            };
            if unsafe { select(0, std::ptr::null_mut(), &mut write, &mut error, &deadline) } <= 0 {
                return Err("DIRECT_CONNECT_TIMEOUT".into());
            }
            let mut code: i32 = 0;
            let mut size = 4;
            if unsafe {
                getsockopt(
                    socket.0,
                    SOL_SOCKET,
                    SO_ERROR,
                    (&mut code as *mut i32).cast(),
                    &mut size,
                )
            } != 0
                || code != 0
            {
                return Err(format!("DIRECT_CONNECT_ERROR:{code}"));
            }
        }
        Ok(started.elapsed().as_micros())
    }
    pub(super) fn measure(
        address: std::net::SocketAddr,
        timeout: Duration,
    ) -> Result<ProbePath, String> {
        let dest = destination(address);
        let (index, source) = physical_source(&dest)?;
        let elapsed_micros = connect_bound(index, &source, &dest, timeout)?;
        Ok(ProbePath {
            interface_index: index,
            source_ip: ip(&source).to_string(),
            destination_ip: address.ip().to_string(),
            elapsed_micros,
        })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn native_bound_socket_closes_after_success_and_failure() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let dest = destination(listener.local_addr().unwrap());
            let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
            let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    GetBestRoute2(
                        std::ptr::null(),
                        0,
                        std::ptr::null(),
                        &dest,
                        0,
                        &mut route,
                        &mut source,
                    )
                },
                0
            );
            for _ in 0..10 {
                assert!(connect_bound(
                    route.InterfaceIndex,
                    &source,
                    &dest,
                    Duration::from_millis(100)
                )
                .is_ok());
                let _ = listener.accept().unwrap();
            }
            assert!(connect_bound(0, &source, &dest, Duration::from_millis(100)).is_err());
            drop(listener);
            assert!(connect_bound(
                route.InterfaceIndex,
                &source,
                &dest,
                Duration::from_millis(100)
            )
            .is_err());
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn read_physical_binding() -> Result<DefaultRouteSnapshot, String> {
    windows::binding_snapshot()
}
pub(crate) fn direct_tcp_probe(
    address: std::net::SocketAddr,
    timeout: Duration,
) -> Result<ProbePath, String> {
    #[cfg(windows)]
    {
        windows::measure(address, timeout)
    }
    #[cfg(not(windows))]
    {
        let _ = (address, timeout);
        Err("DIRECT_UNSUPPORTED_PLATFORM".into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_tun_software_down_and_non_default_routes() {
        assert!(eligible_physical_interface(6, 1, 1, 0, true));
        assert!(eligible_physical_interface(71, 1, 1, 0, true));
        for (kind, flags, status, prefix, gateway) in [
            (6, 0, 1, 0, true),
            (131, 1, 1, 0, true),
            (24, 1, 1, 0, true),
            (6, 1, 2, 0, true),
            (6, 1, 1, 1, true),
            (6, 1, 1, 0, false),
        ] {
            assert!(!eligible_physical_interface(
                kind, flags, status, prefix, gateway
            ));
        }
    }
}
