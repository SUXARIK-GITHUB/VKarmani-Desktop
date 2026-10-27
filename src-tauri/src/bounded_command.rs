use super::*;

const MAX_COMMAND_OUTPUT: usize = 2 * 1024 * 1024;
fn capture_stream(mut stream: impl Read) -> Result<Vec<u8>, String> {
    let mut buffer = [0_u8; 8192];
    let mut output = Vec::new();
    let mut oversized = false;
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| "Command output read failed".to_string())?;
        if count == 0 {
            break;
        }
        if output.len() + count > MAX_COMMAND_OUTPUT {
            oversized = true;
        } else if !oversized {
            output.extend_from_slice(&buffer[..count]);
        }
    }
    if oversized {
        Err("COMMAND_OUTPUT_LIMIT".into())
    } else {
        Ok(output)
    }
}
pub(crate) fn run_command_with_timeout(
    command: Command,
    timeout: Duration,
    context: &str,
) -> Result<String, String> {
    run_command_with_timeout_and_input(command, timeout, context, None)
}
pub(crate) fn run_command_with_timeout_and_input(
    mut command: Command,
    timeout: Duration,
    context: &str,
    input: Option<Vec<u8>>,
) -> Result<String, String> {
    static WORKERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if WORKERS
        .fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |n| (n < 4).then_some(n + 1),
        )
        .is_err()
    {
        return Err("COMMAND_BUSY".into());
    }
    struct Worker;
    impl Drop for Worker {
        fn drop(&mut self) {
            WORKERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
    let _worker = Worker;
    hide_child_console(&mut command);
    let mut child = OwnedXrayProcess::attach(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| format!("Command spawn failed ({context})"))?,
    )?;
    let stdout = child.stdout.take().ok_or("Missing command stdout")?;
    let stderr = child.stderr.take().ok_or("Missing command stderr")?;
    let input_result = write_owned_stdin(&mut child, input)?;
    let (tx_out, rx_out) = std::sync::mpsc::sync_channel(1);
    let (tx_err, rx_err) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx_out.send(capture_stream(stdout));
    });
    std::thread::spawn(move || {
        let _ = tx_err.send(capture_stream(stderr));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(_) => return Err(format!("Command status failed ({context})")),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            let _ = terminate_child_with_timeout(&mut child, Duration::from_millis(500));
            return Err(format!("COMMAND_TIMEOUT: {context}"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(child); // Close job/descendant output handles before collecting readers.
    if let Some(result) = input_result {
        result
            .recv_timeout(Duration::from_millis(500))
            .map_err(|_| "CONFIG_STDIN_DEADLINE")??;
    }
    let remaining = || {
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2))
    };
    let stdout = rx_out
        .recv_timeout(remaining())
        .map_err(|_| "Command stdout deadline".to_string())??;
    let stderr = rx_err
        .recv_timeout(remaining())
        .map_err(|_| "Command stderr deadline".to_string())??;
    if status.success() {
        Ok(String::from_utf8_lossy(&stdout).trim().to_string())
    } else {
        let text = if stderr.is_empty() { &stdout } else { &stderr };
        Err(format!(
            "Command failed ({context}): {}",
            redact_sensitive(&String::from_utf8_lossy(text))
        ))
    }
}

pub(crate) fn write_owned_stdin(
    child: &mut OwnedXrayProcess,
    input: Option<Vec<u8>>,
) -> Result<Option<std::sync::mpsc::Receiver<Result<(), String>>>, String> {
    let Some(input) = input else {
        return Ok(None);
    };
    let mut pipe = child.stdin.take().ok_or("CONFIG_STDIN_MISSING")?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = pipe
            .write_all(&input)
            .map_err(|_| "CONFIG_STDIN_WRITE_FAILED".to_string());
        drop(pipe); // EOF is part of Xray's existing stdin: protocol.
        let _ = tx.send(result);
    });
    Ok(Some(rx))
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    fn powershell(script: &str) -> Command {
        let mut c = Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        c.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        c
    }
    #[test]
    fn drains_both_pipes_before_exit_and_caps_capture() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let output = run_command_with_timeout(
            powershell(
                "[Console]::Out.Write(('a' * 100000)); [Console]::Error.Write(('e' * 100000))",
            ),
            Duration::from_secs(8),
            "synthetic large stdout/stderr",
        )
        .unwrap();
        assert_eq!(output.len(), 100000);
        assert!(
            capture_stream(std::io::Cursor::new(vec![b'x'; MAX_COMMAND_OUTPUT + 1]))
                .unwrap_err()
                .starts_with("COMMAND_OUTPUT_LIMIT")
        );
    }
    #[test]
    fn timeout_stops_only_owned_job_with_bounded_caller() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let start = Instant::now();
        assert!(run_command_with_timeout(
            powershell("Start-Sleep -Seconds 20"),
            Duration::from_millis(200),
            "synthetic timeout"
        )
        .unwrap_err()
        .starts_with("COMMAND_TIMEOUT"));
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn stdin_delivers_bytes_and_eof_and_does_not_hang_on_early_exit() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let mut command = powershell("[Console]::Out.Write([Console]::In.ReadToEnd())");
        command.stdin(Stdio::piped());
        assert_eq!(
            run_command_with_timeout_and_input(
                command,
                Duration::from_secs(8),
                "synthetic stdin EOF",
                Some(b"synthetic-no-secret".to_vec())
            )
            .unwrap(),
            "synthetic-no-secret"
        );
        let mut command = powershell("exit 0");
        command.stdin(Stdio::piped());
        assert!(run_command_with_timeout_and_input(
            command,
            Duration::from_secs(8),
            "synthetic stdin closed",
            Some(vec![b'x'; 1024 * 1024])
        )
        .is_err());
        let mut command = powershell("Start-Sleep -Seconds 20");
        command.stdin(Stdio::piped());
        assert!(run_command_with_timeout_and_input(
            command,
            Duration::from_millis(200),
            "synthetic blocked stdin",
            Some(vec![b'x'; 1024 * 1024])
        )
        .unwrap_err()
        .starts_with("COMMAND_TIMEOUT"));
    }
}
