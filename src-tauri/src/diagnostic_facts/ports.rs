//! TCP listener tables only: no bind/connect/kill, no foreign PID/path export.
use super::*;
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6},
};
#[derive(Clone, Copy)]
struct Listener {
    port: u16,
    pid: u32,
    ipv6_wildcard: bool,
}
fn table(family: u32) -> Result<Vec<Listener>, String> {
    let mut bytes = 0;
    let result = unsafe {
        GetExtendedTcpTable(
            null_mut(),
            &mut bytes,
            0,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if result != ERROR_INSUFFICIENT_BUFFER {
        return Err("PORT_TABLE_UNAVAILABLE".into());
    }
    for _ in 0..3 {
        if !(4..=1024 * 1024).contains(&bytes) {
            return Err("PORT_TABLE_LIMIT".into());
        }
        let mut buffer = vec![0u32; (bytes as usize).div_ceil(4)];
        let mut used = (buffer.len() * 4) as u32;
        let result = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &mut used,
                0,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if result == ERROR_INSUFFICIENT_BUFFER {
            bytes = used;
            continue;
        }
        if result != ERROR_SUCCESS || used as usize > buffer.len() * 4 || used < 4 {
            return Err("PORT_TABLE_UNAVAILABLE".into());
        }
        return decode(&buffer, used as usize, family);
    }
    Err("PORT_TABLE_CHANGED".into())
}
fn decode(buffer: &[u32], bytes: usize, family: u32) -> Result<Vec<Listener>, String> {
    if bytes < 4 || bytes > std::mem::size_of_val(buffer) {
        return Err("PORT_TABLE_INVALID".into());
    }
    let count = buffer[0] as usize;
    let row_size = match family {
        x if x == AF_INET as u32 => std::mem::size_of::<MIB_TCPROW_OWNER_PID>(),
        x if x == AF_INET6 as u32 => std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>(),
        _ => return Err("PORT_TABLE_INVALID".into()),
    };
    if count > 16384 || count > (bytes - 4) / row_size {
        return Err("PORT_TABLE_INVALID".into());
    }
    let mut listeners = vec![];
    for index in 0..count {
        let pointer = unsafe { buffer.as_ptr().cast::<u8>().add(4 + index * row_size) };
        if family == AF_INET as u32 {
            let row = unsafe { std::ptr::read_unaligned(pointer.cast::<MIB_TCPROW_OWNER_PID>()) };
            if row.dwState != MIB_TCP_STATE_LISTEN as u32
                || !(row.dwLocalAddr == 0 || row.dwLocalAddr.to_ne_bytes() == [127, 0, 0, 1])
            {
                continue;
            }
            listeners.push(Listener {
                port: u16::from_be(row.dwLocalPort as u16),
                pid: row.dwOwningPid,
                ipv6_wildcard: false,
            });
        } else {
            let row = unsafe { std::ptr::read_unaligned(pointer.cast::<MIB_TCP6ROW_OWNER_PID>()) };
            // :: and IPv4-mapped loopback might cover the IPv4 endpoints. TCP
            // table does not reveal IPV6_V6ONLY, so this is uncertainty, not
            // proof of a conflict. ::1 alone does not occupy127.0.0.1.
            let mapped_loopback = row.ucLocalAddr[..10] == [0; 10]
                && row.ucLocalAddr[10..12] == [255, 255]
                && (row.ucLocalAddr[12..] == [127, 0, 0, 1]
                    || row.ucLocalAddr[12..] == [0, 0, 0, 0]);
            if row.dwState != MIB_TCP_STATE_LISTEN as u32
                || (row.ucLocalAddr != [0; 16] && !mapped_loopback)
            {
                continue;
            }
            listeners.push(Listener {
                port: u16::from_be(row.dwLocalPort as u16),
                pid: row.dwOwningPid,
                ipv6_wildcard: true,
            });
        }
    }
    Ok(listeners)
}
fn classify(port: u16, listeners: &[Listener], expected: Option<u32>) -> &'static str {
    let relevant = listeners
        .iter()
        .filter(|row| row.port == port)
        .collect::<Vec<_>>();
    if relevant
        .iter()
        .any(|row| !row.ipv6_wildcard && row.pid != 0 && Some(row.pid) != expected)
    {
        return "foreign";
    }
    if relevant.iter().any(|row| row.ipv6_wildcard || row.pid == 0) {
        return "unconfirmed";
    }
    if relevant.is_empty() {
        return "free";
    }
    "owned"
}
pub(super) fn observe(expected: Option<u32>) -> Vec<PortObservation> {
    summarize(table(AF_INET as u32), table(AF_INET6 as u32), expected)
}
pub(crate) fn runtime_ports_ready(pid: u32) -> Result<bool, String> {
    // Startup targets these exact IPv4 endpoints. A confirmed IPv4 listener
    // need not wait for an unrelated/disabled IPv6 stack. Diagnostics still
    // reports the broader IPv6 ambiguity; this is not a bind reservation.
    readiness(&summarize(table(AF_INET as u32), Ok(vec![]), Some(pid)))
}
fn readiness(ports: &[PortObservation]) -> Result<bool, String> {
    if ports.iter().any(|p| p.state == "foreign") {
        return Err("CORE_PORT_CONFLICT: a runtime listener belongs to another process; no foreign process was stopped".into());
    }
    Ok(ports.len() == 3 && ports.iter().all(|p| p.state == "owned"))
}
fn summarize(
    ipv4: Result<Vec<Listener>, String>,
    ipv6: Result<Vec<Listener>, String>,
    expected: Option<u32>,
) -> Vec<PortObservation> {
    [SOCKS_PORT, HTTP_PORT, XRAY_API_PORT]
        .into_iter()
        .map(|port| PortObservation {
            port,
            state: match (&ipv4, &ipv6) {
                (Ok(rows), _) if classify(port, rows, expected) == "foreign" => "foreign",
                (Ok(v4), Ok(v6)) => {
                    let mut rows = v4.clone();
                    rows.extend_from_slice(v6);
                    classify(port, &rows, expected)
                }
                _ => "unavailable",
            },
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_never_borrows_foreign_listener_or_accepts_missing_unknown_or_partial_tables() {
        let own = [SOCKS_PORT, HTTP_PORT, XRAY_API_PORT].map(|port| Listener {
            port,
            pid: 17,
            ipv6_wildcard: false,
        });
        assert!(readiness(&summarize(Ok(own.to_vec()), Ok(vec![]), Some(17))).unwrap());
        assert!(!readiness(&summarize(Ok(own[..2].to_vec()), Ok(vec![]), Some(17))).unwrap());
        assert!(
            readiness(&summarize(Ok(own.to_vec()), Ok(vec![]), Some(18)))
                .unwrap_err()
                .starts_with("CORE_PORT_CONFLICT")
        );
        assert!(!readiness(&summarize(Ok(own.to_vec()), Err("denied".into()), Some(17))).unwrap());
        assert!(!readiness(&summarize(
            Ok(own.to_vec()),
            Ok(vec![Listener {
                port: SOCKS_PORT,
                pid: 17,
                ipv6_wildcard: true
            }]),
            Some(17)
        ))
        .unwrap());
        assert!(!readiness(&[]).unwrap());
    }
    #[test]
    fn malformed_tcp_tables_do_not_read_outside_buffer() {
        for (buffer, bytes, family) in [
            (vec![], 0, AF_INET as u32),
            (vec![u32::MAX], 4, AF_INET as u32),
            (vec![1, 0], 8, AF_INET6 as u32),
            (vec![0], 8, AF_INET as u32),
            (vec![0], 4, 999),
        ] {
            assert!(decode(&buffer, bytes, family).is_err());
        }
        assert!(decode(&[0], 4, AF_INET as u32).unwrap().is_empty());
    }
    #[test]
    fn ipv6_unknowns_never_hide_known_ipv4_conflicts_or_become_free() {
        let foreign = Listener {
            port: SOCKS_PORT,
            pid: 99,
            ipv6_wildcard: false,
        };
        let rows = summarize(
            Ok(vec![foreign]),
            Err("injected API failure".into()),
            Some(17),
        );
        assert_eq!(rows[0].state, "foreign");
        assert!(rows[1..].iter().all(|row| row.state == "unavailable"));
        assert!(summarize(Err("denied".into()), Ok(vec![]), None)
            .iter()
            .all(|row| row.state == "unavailable"));
    }
    #[test]
    fn ipv6_wildcard_and_mapped_loopback_are_uncertain_but_v6_loopback_does_not_cover_ipv4() {
        let mut buffer = vec![0u32; 1 + std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>() / 4];
        buffer[0] = 1;
        let mut row: MIB_TCP6ROW_OWNER_PID = unsafe { std::mem::zeroed() };
        row.dwLocalPort = SOCKS_PORT.to_be() as u32;
        row.dwState = MIB_TCP_STATE_LISTEN as u32;
        row.dwOwningPid = 17;
        for address in [
            [0; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1],
        ] {
            row.ucLocalAddr = address;
            unsafe {
                std::ptr::write_unaligned(buffer.as_mut_ptr().add(1).cast(), row);
            }
            let rows = decode(&buffer, buffer.len() * 4, AF_INET6 as u32).unwrap();
            assert_eq!(classify(SOCKS_PORT, &rows, Some(17)), "unconfirmed");
        }
        row.ucLocalAddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        unsafe {
            std::ptr::write_unaligned(buffer.as_mut_ptr().add(1).cast(), row);
        }
        assert!(decode(&buffer, buffer.len() * 4, AF_INET6 as u32)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn classification_never_turns_unknown_ipv6_or_pid_into_owned_or_free() {
        let own = Listener {
            port: 17,
            pid: 5,
            ipv6_wildcard: false,
        };
        assert_eq!(classify(17, &[], Some(5)), "free");
        assert_eq!(classify(17, &[own], Some(5)), "owned");
        assert_eq!(classify(17, &[own], None), "foreign");
        assert_eq!(
            classify(17, &[own, Listener { pid: 9, ..own }], Some(5)),
            "foreign"
        );
        assert_eq!(
            classify(17, &[Listener { pid: 0, ..own }], Some(5)),
            "unconfirmed"
        );
        assert_eq!(
            classify(
                17,
                &[Listener {
                    ipv6_wildcard: true,
                    ..own
                }],
                Some(5)
            ),
            "unconfirmed"
        );
        assert_eq!(classify(18, &[own], Some(5)), "free");
    }
    #[test]
    fn ipv4_decoder_preserves_network_port_order_and_ignores_other_interfaces() {
        let mut buffer = vec![0u32; 1 + std::mem::size_of::<MIB_TCPROW_OWNER_PID>() / 4];
        buffer[0] = 1;
        let row = MIB_TCPROW_OWNER_PID {
            dwState: MIB_TCP_STATE_LISTEN as u32,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: 10808u16.to_be() as u32,
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 5,
        };
        unsafe {
            std::ptr::write_unaligned(buffer.as_mut_ptr().add(1).cast(), row);
        }
        let rows = decode(&buffer, buffer.len() * 4, AF_INET as u32).unwrap();
        assert_eq!(rows[0].port, 10808);
        assert_eq!(rows[0].pid, 5);
        buffer[2] = u32::from_ne_bytes([192, 0, 2, 1]);
        assert!(decode(&buffer, buffer.len() * 4, AF_INET as u32)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn read_only_table_identifies_only_an_owned_ephemeral_test_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let rows = table(AF_INET as u32).unwrap();
        assert_eq!(classify(port, &rows, Some(std::process::id())), "owned");
        drop(listener);
    }
}
