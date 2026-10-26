// Read-only readiness: reachability alone cannot establish who bound a port.
#[cfg(any(target_os = "windows", test))]
fn table_has_owned_loopback_listeners(
    bytes: &[u8],
    expected_pid: u32,
    ports: &[u16],
) -> Result<bool, String> {
    const ROW_BYTES: usize = 24; // MIB_TCPROW_OWNER_PID: six DWORD fields
    let invalid = || "XRAY_LISTENER_TABLE_INVALID".to_string();
    let count =
        u32::from_ne_bytes(bytes.get(..4).ok_or_else(invalid)?.try_into().unwrap()) as usize;
    let end = count
        .checked_mul(ROW_BYTES)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(invalid)?;
    if end > bytes.len() || expected_pid == 0 || ports.is_empty() || ports.contains(&0) {
        return Err(invalid());
    }
    let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
    let rows = &bytes[4..end];
    let mut found = vec![false; ports.len()];
    for row in rows.chunks_exact(ROW_BYTES) {
        let word = |offset| u32::from_ne_bytes(row[offset..offset + 4].try_into().unwrap());
        let address = word(4);
        let port = u16::from_be(word(8) as u16);
        if word(0) != 2 || (address != loopback && address != 0) {
            continue;
        }
        for (index, required) in ports.iter().enumerate() {
            if port == *required {
                if word(20) != expected_pid {
                    return Ok(false);
                }
                // A wildcard-only bind is not the private loopback bind we asked for.
                found[index] |= address == loopback;
            }
        }
    }
    Ok(found.into_iter().all(|ready| ready))
}

pub(crate) fn owned_loopback_listeners_ready(pid: u32, ports: &[u16]) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::{
            Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
            NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER},
            Networking::WinSock::AF_INET,
        };
        let mut size = 0u32;
        // A u32 buffer supplies the DWORD alignment required by the Windows table.
        for _ in 0..3 {
            if size > 4 * 1024 * 1024 {
                return Err("XRAY_LISTENER_TABLE_TOO_LARGE".into());
            }
            let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
            let capacity = buffer.len() * 4;
            let pointer = if buffer.is_empty() {
                std::ptr::null_mut()
            } else {
                buffer.as_mut_ptr().cast()
            };
            // SAFETY: aligned writable buffer of at least input size; Reserved=0.
            let code = unsafe {
                GetExtendedTcpTable(
                    pointer,
                    &mut size,
                    0,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if code == NO_ERROR && size as usize <= capacity {
                // SAFETY: initialized u32 storage, bounded by the allocated capacity.
                let bytes = unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size as usize)
                };
                return table_has_owned_loopback_listeners(bytes, pid, ports);
            }
            if code != ERROR_INSUFFICIENT_BUFFER {
                return Err(format!("XRAY_LISTENER_TABLE_FAILED: {code}"));
            }
            // Retry only the documented size-growth result, never an API failure.
        }
        Err("XRAY_LISTENER_TABLE_CHANGED".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (pid, ports);
        Err("XRAY_LISTENER_OWNERSHIP_UNSUPPORTED".into())
    }
}

fn ready_from_owner_snapshot(
    owned: Result<bool, String>,
    check_retained_child: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    if !owned? {
        return Ok(false);
    }
    check_retained_child()?;
    Ok(true)
}

pub(crate) fn child_listeners_ready(
    child: &mut std::process::Child,
    ports: &[u16],
) -> Result<bool, String> {
    ready_from_owner_snapshot(owned_loopback_listeners_ready(child.id(), ports), || {
        retained_child_alive(child)
    })
}

pub(crate) fn require_proxy_runtime_ready(
    child: &mut std::process::Child,
    ports: &[u16],
) -> Result<(), String> {
    if !child_listeners_ready(child, ports)? {
        return Err("PROXY_RUNTIME_NOT_READY: owned Xray listeners unavailable.".into());
    }
    Ok(())
}

fn retained_child_alive(child: &mut std::process::Child) -> Result<(), String> {
    // Keep using this Child's HANDLE, never reopen a process by numeric PID.
    match child
        .try_wait()
        .map_err(|_| "XRAY_READINESS_EXIT_UNKNOWN")?
    {
        Some(status) => Err(format!("XRAY_EXITED_DURING_READINESS: {:?}", status.code())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn table(rows: &[[u32; 6]]) -> Vec<u8> {
        let mut bytes = (rows.len() as u32).to_ne_bytes().to_vec();
        for row in rows {
            for word in row {
                bytes.extend(word.to_ne_bytes());
            }
        }
        bytes
    }
    fn listener(pid: u32, address: [u8; 4], port: u16) -> [u32; 6] {
        [
            2,
            u32::from_ne_bytes(address),
            port.to_be() as u32,
            0,
            0,
            pid,
        ]
    }
    #[test]
    fn only_complete_exact_owner_loopback_binds_are_ready() {
        let ports = [10808, 10809, 10999];
        let rows: Vec<_> = ports
            .iter()
            .map(|port| listener(44, [127, 0, 0, 1], *port))
            .collect();
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&rows), 44, &ports),
            Ok(true)
        );
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&rows), 45, &ports),
            Ok(false)
        );
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&rows[..2]), 44, &ports),
            Ok(false)
        );
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&[]), 44, &ports),
            Ok(false)
        );
        let mut mixed = rows.clone();
        mixed[2][20 / 4] = 45;
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&mixed), 44, &ports),
            Ok(false)
        );
        let mut closed = rows.clone();
        closed[0][0] = 5;
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&closed), 44, &ports),
            Ok(false)
        );
    }
    #[test]
    fn foreign_wildcard_or_loopback_is_rejected_in_either_order() {
        let owned = listener(44, [127, 0, 0, 1], 10808);
        for address in [[0, 0, 0, 0], [127, 0, 0, 1]] {
            let foreign = listener(45, address, 10808);
            for rows in [[owned, foreign], [foreign, owned]] {
                assert_eq!(
                    table_has_owned_loopback_listeners(&table(&rows), 44, &[10808]),
                    Ok(false)
                );
            }
        }
        let elsewhere = listener(45, [192, 0, 2, 1], 10808);
        assert_eq!(
            table_has_owned_loopback_listeners(&table(&[owned, elsewhere]), 44, &[10808]),
            Ok(true)
        );
        assert_eq!(
            table_has_owned_loopback_listeners(
                &table(&[listener(44, [0; 4], 10808)]),
                44,
                &[10808]
            ),
            Ok(false)
        );
    }
    #[test]
    fn malformed_tables_and_invalid_intent_fail_closed() {
        for bytes in [
            vec![],
            vec![0; 3],
            u32::MAX.to_ne_bytes().to_vec(),
            vec![1, 0, 0, 0, 0],
        ] {
            assert!(table_has_owned_loopback_listeners(&bytes, 44, &[10808]).is_err());
        }
        for (pid, ports) in [(0, vec![10808]), (44, vec![]), (44, vec![0])] {
            assert!(table_has_owned_loopback_listeners(&table(&[]), pid, &ports).is_err());
        }
    }
    #[test]
    fn reused_pid_or_exit_after_snapshot_cannot_pass_a_dead_retained_child() {
        let rows = table(&[listener(44, [127, 0, 0, 1], 10808)]);
        for reason in [
            "XRAY_EXITED_DURING_READINESS",
            "XRAY_READINESS_EXIT_UNKNOWN",
        ] {
            // Even a matching numeric PID in a stale/reused table is insufficient.
            assert_eq!(
                ready_from_owner_snapshot(
                    table_has_owned_loopback_listeners(&rows, 44, &[10808]),
                    || Err(reason.into())
                ),
                Err(reason.into())
            );
        }
        assert_eq!(
            ready_from_owner_snapshot(Ok(false), || panic!(
                "foreign/missing listener is not Ready"
            )),
            Ok(false)
        );
        assert_eq!(
            ready_from_owner_snapshot(Err("TABLE_UNKNOWN".into()), || panic!(
                "unknown table must not pass"
            )),
            Err("TABLE_UNKNOWN".into())
        );
    }
    #[test]
    #[cfg(target_os = "windows")]
    #[ignore = "CI-only isolated loopback socket; do not run native trials on the owner's PC"]
    fn windows_socket_owner_integration() {
        use std::io::{BufRead, Write};
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        };
        assert_eq!(
            std::env::var("GITHUB_ACTIONS").as_deref(),
            Ok("true"),
            "disposable CI runner only"
        );
        if let Ok(requested) = std::env::var("VKARMANI_LISTENER_FIXTURE_PORT") {
            let port: u16 = requested.parse().unwrap();
            let bound = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port));
            if port != 0 {
                assert!(bound.is_err());
                println!("BIND_REFUSED");
                return;
            }
            let socket = bound.unwrap();
            println!(
                "OWNER_READY {} {}",
                std::process::id(),
                socket.local_addr().unwrap().port()
            );
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            assert_eq!(input.trim(), "CLOSE");
            drop(socket);
            println!("OWNER_CLOSED");
            std::io::stdout().flush().unwrap();
            input.clear();
            std::io::stdin().read_line(&mut input).unwrap();
            assert_eq!(input.trim(), "EXIT");
            return;
        }
        fn spawn_fixture(
            port: u16,
        ) -> (crate::OwnedXrayProcess, std::sync::mpsc::Receiver<String>) {
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "listener_owner::tests::windows_socket_owner_integration",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("VKARMANI_LISTENER_FIXTURE_PORT", port.to_string())
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            // Retained process HANDLE and kill-on-close job; cleanup never reopens a PID.
            let mut child = crate::OwnedXrayProcess::attach(child).unwrap();
            let stdout = child.stdout.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            (child, rx)
        }
        fn receive(rx: &std::sync::mpsc::Receiver<String>, prefix: &str) -> String {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let line = rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("bounded fixture handshake");
                if let Some(at) = line.find(prefix) {
                    return line[at..].to_string();
                }
            }
        }
        fn wait_exit(child: &mut std::process::Child) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "fixture exit deadline");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        fn probe_state(child: crate::OwnedXrayProcess) -> crate::AppState {
            let state = crate::AppState::default();
            *state.runtime.lock().unwrap() = Some(crate::ManagedCore {
                child,
                core_path: String::new(),
                config_path: String::new(),
                config_hash: String::new(),
                request_hash: String::new(),
                log_path: String::new(),
                server_id: String::new(),
                server_fingerprint: None,
                started_at: "synthetic-start".into(),
                telemetry_epoch: 1,
                network_mode: "proxy".into(),
                tun_interface_name: None,
                tun_server_ips: Vec::new(),
                self_restart_count: 0,
                last_self_restart_at: None,
                physical_binding: None,
            });
            state
        }
        assert_eq!(std::mem::size_of::<MIB_TCPROW_OWNER_PID>(), 24);
        assert_eq!(std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table), 4);
        let socket = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let pid = std::process::id();
        assert_eq!(owned_loopback_listeners_ready(pid, &[port]), Ok(true));
        assert_eq!(
            owned_loopback_listeners_ready(pid.wrapping_add(1).max(1), &[port]),
            Ok(false)
        );
        drop(socket);
        assert_eq!(owned_loopback_listeners_ready(pid, &[port]), Ok(false));
        let occupied = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let (mut rejected, messages) = spawn_fixture(occupied_port);
        receive(&messages, "BIND_REFUSED");
        wait_exit(&mut rejected);
        assert_eq!(
            owned_loopback_listeners_ready(pid, &[occupied_port]),
            Ok(true)
        );
        // Two independent launches exercise restart without reusing an old handle.
        for _ in 0..2 {
            let (child, messages) = spawn_fixture(0);
            let ready = receive(&messages, "OWNER_READY ");
            let fields: Vec<_> = ready.split_whitespace().collect();
            assert_eq!(fields[1].parse::<u32>().unwrap(), child.id());
            let port = fields[2].parse::<u16>().unwrap();
            let state = probe_state(child);
            let identity =
                crate::connectivity_probe_runtime_identity(&state, None, &[port]).unwrap();
            assert!(crate::connectivity_probe_runtime_identity(
                &state,
                Some(&identity),
                &[occupied_port]
            )
            .is_err());
            // A new per-launch epoch invalidates an in-flight HTTP response even
            // when numeric PID/start text is unchanged (synthetic reuse window).
            state
                .runtime
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .telemetry_epoch += 1;
            assert_eq!(
                crate::connectivity_probe_runtime_identity(&state, Some(&identity), &[port])
                    .unwrap_err(),
                "CONNECTIVITY_RUNTIME_SUPERSEDED"
            );
            let fresh = crate::connectivity_probe_runtime_identity(&state, None, &[port]).unwrap();
            assert_ne!(identity, fresh);
            assert_eq!(
                crate::connectivity_probe_runtime_identity(&state, Some(&fresh), &[port]).unwrap(),
                fresh
            );
            let mut child = state.runtime.lock().unwrap().take().unwrap().child;
            assert_eq!(child_listeners_ready(&mut child, &[port]), Ok(true));
            assert_eq!(require_proxy_runtime_ready(&mut child, &[port]), Ok(()));
            assert_eq!(owned_loopback_listeners_ready(pid, &[port]), Ok(false));
            assert_eq!(
                child_listeners_ready(&mut child, &[occupied_port]),
                Ok(false)
            );
            assert!(require_proxy_runtime_ready(&mut child, &[occupied_port])
                .unwrap_err()
                .starts_with("PROXY_RUNTIME_NOT_READY"));
            assert!(child.try_wait().unwrap().is_none());
            child.stdin.as_mut().unwrap().write_all(b"CLOSE\n").unwrap();
            receive(&messages, "OWNER_CLOSED");
            assert!(child.try_wait().unwrap().is_none());
            assert_eq!(child_listeners_ready(&mut child, &[port]), Ok(false));
            assert!(require_proxy_runtime_ready(&mut child, &[port]).is_err());
            let state = probe_state(child);
            assert!(crate::connectivity_probe_runtime_identity(&state, None, &[port]).is_err());
            let mut child = state.runtime.lock().unwrap().take().unwrap().child;
            child.stdin.as_mut().unwrap().write_all(b"EXIT\n").unwrap();
            wait_exit(&mut child);
            assert!(require_proxy_runtime_ready(&mut child, &[port]).is_err());
            // Simulate a stale/reused-PID table after actual child exit. Its
            // retained HANDLE remains authoritative, so that snapshot is refused.
            assert!(
                ready_from_owner_snapshot(Ok(true), || retained_child_alive(&mut child))
                    .unwrap_err()
                    .starts_with("XRAY_EXITED_DURING_READINESS")
            );
        }
    }
}
