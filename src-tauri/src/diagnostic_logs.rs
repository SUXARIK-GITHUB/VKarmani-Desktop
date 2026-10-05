use super::*;

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
const RETAIN_LOG_BYTES: u64 = MAX_LOG_BYTES / 2;
static LOG_WRITE_LOCK: Mutex<()> = Mutex::new(());
struct SafeLog {
    file: File,
    _parents: Vec<File>,
}
fn open_safe_log(path: &Path, writable: bool) -> Result<Option<SafeLog>, String> {
    let parents = lock_runtime_parent_paths(path)?;
    let mut options = OpenOptions::new();
    options
        .create(writable)
        .truncate(false)
        .write(writable)
        .read(true);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if !writable && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("LOG_OPEN".into()),
    };
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::*;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
            || info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
        {
            return Err("LOG_UNSAFE_FILE".into());
        }
    }
    Ok(Some(SafeLog {
        file,
        _parents: parents,
    }))
}
pub(crate) fn validate_or_create_log(path: &Path) -> Result<(), String> {
    let _guard = LOG_WRITE_LOCK.lock().map_err(|_| "LOG_LOCK")?;
    open_safe_log(path, true)?
        .ok_or_else(|| "LOG_OPEN".into())
        .map(|_| ())
}
#[cfg(test)]
pub(crate) fn reset_bounded_log(path: &Path) -> Result<(), String> {
    let _guard = LOG_WRITE_LOCK.lock().map_err(|_| "LOG_LOCK")?;
    let log = open_safe_log(path, true)?.ok_or("LOG_OPEN")?;
    log.file.set_len(0).map_err(|_| "LOG_TRUNCATE".into())
}
pub(crate) fn append_bounded_log(path: &Path, line: &str) -> Result<(), String> {
    let _guard = LOG_WRITE_LOCK.lock().map_err(|_| "LOG_LOCK")?;
    let mut log = open_safe_log(path, true)?.ok_or("LOG_OPEN")?;
    let line = redact_sensitive(&line.chars().take(4096).collect::<String>());
    if log.file.metadata().map_err(|_| "LOG_METADATA")?.len() + line.len() as u64 + 1
        > MAX_LOG_BYTES
    {
        // Read only a bounded tail, discard its partial first line (which can
        // start inside UTF-8 or a credential), and redact complete lines again.
        let size = log.file.metadata().map_err(|_| "LOG_METADATA")?.len();
        let start = size.saturating_sub(RETAIN_LOG_BYTES);
        log.file
            .seek(SeekFrom::Start(start))
            .map_err(|_| "LOG_SEEK")?;
        let mut bytes = Vec::new();
        (&mut log.file)
            .take(RETAIN_LOG_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|_| "LOG_READ")?;
        let content = String::from_utf8_lossy(&bytes);
        let complete = if start > 0 {
            content.split_once('\n').map(|(_, tail)| tail).unwrap_or("")
        } else {
            &content
        };
        let retained = complete
            .lines()
            .map(|row| redact_sensitive(&row.chars().take(4096).collect::<String>()))
            .collect::<Vec<_>>()
            .join("\n");
        // Redaction can expand short credentials. Bound the resulting bytes,
        // trimming at a complete line rather than at a UTF-8 byte boundary.
        let retained = if retained.len() > RETAIN_LOG_BYTES as usize {
            retained.as_bytes()[retained.len() - RETAIN_LOG_BYTES as usize..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| &retained[retained.len() - RETAIN_LOG_BYTES as usize + offset + 1..])
                .unwrap_or("")
        } else {
            &retained
        };
        log.file.set_len(0).map_err(|_| "LOG_TRUNCATE")?;
        log.file.seek(SeekFrom::Start(0)).map_err(|_| "LOG_SEEK")?;
        writeln!(
            log.file,
            "[VKarmani log compacted; oldest lines discarded]\n{retained}"
        )
        .map_err(|_| "LOG_WRITE")?;
    }
    log.file.seek(SeekFrom::End(0)).map_err(|_| "LOG_SEEK")?;
    writeln!(log.file, "{line}").map_err(|_| "LOG_WRITE".into())
}
fn drain_lines(mut reader: impl Read, path: &Path) {
    let mut buffer = [0u8; 4096];
    let mut line = Vec::with_capacity(4096);
    let mut oversized = false;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        for byte in &buffer[..count] {
            if *byte == b'\n' {
                let text = if oversized {
                    "[oversized Xray log line omitted]".into()
                } else {
                    String::from_utf8_lossy(&line).into_owned()
                };
                let _ = append_bounded_log(path, &text);
                line.clear();
                oversized = false;
            } else if line.len() < 16 * 1024 && !oversized {
                line.push(*byte);
            } else {
                line.clear();
                oversized = true;
            }
        }
    }
    if !line.is_empty() && !oversized {
        let _ = append_bounded_log(path, &String::from_utf8_lossy(&line));
    }
}
pub(crate) fn drain_runtime_log(reader: impl Read + Send + 'static, path: PathBuf) {
    std::thread::spawn(move || drain_lines(reader, &path));
}

fn bounded_log_tail(path: &Path, lines: usize) -> Result<Vec<String>, String> {
    const MAX_BYTES: u64 = 128 * 1024;
    let _guard = LOG_WRITE_LOCK.lock().map_err(|_| "LOG_LOCK")?;
    let mut log = match open_safe_log(path, false)? {
        Some(log) => log,
        None => return Ok(vec![]),
    };
    let size = log.file.metadata().map_err(|_| "LOG_METADATA")?.len();
    let start = size.saturating_sub(MAX_BYTES);
    log.file
        .seek(SeekFrom::Start(start))
        .map_err(|_| "LOG_SEEK")?;
    let mut bytes = Vec::new();
    (&mut log.file)
        .take(MAX_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| "LOG_READ")?;
    let content = String::from_utf8_lossy(&bytes);
    let content = if start > 0 {
        content.split_once('\n').map(|(_, tail)| tail).unwrap_or("")
    } else {
        &content
    };
    let mut result = content
        .lines()
        .rev()
        .take(lines.clamp(1, 200))
        .map(|line| redact_sensitive(&line.chars().take(4096).collect::<String>()))
        .collect::<Vec<_>>();
    result.reverse();
    Ok(result)
}
pub(crate) fn read_runtime_log_excerpt(path: &Path, lines: usize) -> Vec<String> {
    bounded_log_tail(path, lines).unwrap_or_default()
}
pub(crate) fn tail_runtime_log(app: &AppHandle, lines: usize) -> Result<Vec<String>, String> {
    bounded_log_tail(&runtime_log_path(app)?, lines)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_keeps_recent_utf8_and_redacts_preserved_lines() {
        let path =
            std::env::temp_dir().join(format!("vkarmani-log-rotation-{}.txt", std::process::id()));
        let recent =
            "\nuseful before rotation Я\nAuthorization: Bearer synthetic-rotation-secret\n";
        fs::write(
            &path,
            format!("{}{}", "x".repeat(MAX_LOG_BYTES as usize), recent),
        )
        .unwrap();
        append_bounded_log(&path, "latest Ю").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("useful before rotation Я"));
        assert!(text.contains("latest Ю"));
        assert!(!text.contains("synthetic-rotation-secret"));
        assert!(fs::metadata(&path).unwrap().len() <= MAX_LOG_BYTES);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn repeated_unicode_rotations_keep_disk_and_reader_bounded() {
        let path =
            std::env::temp_dir().join(format!("vkarmani-log-stress-{}.txt", std::process::id()));
        let _ = fs::remove_file(&path);
        for index in 0..2400 {
            append_bounded_log(&path, &format!("event {index} {}", "Ю".repeat(3000))).unwrap();
            assert!(fs::metadata(&path).unwrap().len() <= MAX_LOG_BYTES);
        }
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("event 2399"));
        assert!(text.contains("event 2398"));
        assert!(bounded_log_tail(&path, usize::MAX).unwrap().len() <= 200);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn rotation_byte_limit_survives_redaction_expansion_and_utf8_boundary() {
        let path =
            std::env::temp_dir().join(format!("vkarmani-log-expansion-{}.txt", std::process::id()));
        let contents = format!(
            "{}\n{}\nuseful recent Ю\n",
            "Я".repeat(MAX_LOG_BYTES as usize / 2),
            "key=x\n".repeat(160_000)
        );
        fs::write(&path, contents).unwrap();
        append_bounded_log(&path, "latest data Я").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("key=x"));
        assert!(text.contains("useful recent Ю"));
        assert!(text.ends_with("latest data Я\n"));
        assert!(fs::metadata(&path).unwrap().len() <= MAX_LOG_BYTES);
        fs::remove_file(path).unwrap();
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn hardlinked_log_is_rejected_without_modifying_target() {
        let dir = std::env::temp_dir().join(format!("vkarmani-log-link-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let target = dir.join("target.txt");
        let link = dir.join("log.txt");
        fs::write(&target, b"preserve").unwrap();
        fs::hard_link(&target, &link).unwrap();
        assert!(append_bounded_log(&link, "unsafe").is_err());
        assert!(reset_bounded_log(&link).is_err());
        assert!(bounded_log_tail(&link, 10).is_err());
        assert!(ensure_log_file(&link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve");
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn disk_and_pipe_lines_are_bounded_and_credentials_redacted() {
        let path =
            std::env::temp_dir().join(format!("vkarmani-capped-log-{}.txt", std::process::id()));
        fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
        drain_lines(
            std::io::Cursor::new(format!(
                "{}\nAuthorization: Bearer abcde\nlast Я\n",
                "x".repeat(100000)
            )),
            &path,
        );
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("oversized"));
        assert!(!text.contains("abcde"));
        assert!(text.contains("last Я"));
        assert!(fs::metadata(&path).unwrap().len() <= MAX_LOG_BYTES);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn huge_unicode_tail_is_bounded_and_missing_logs_are_empty() {
        let path = std::env::temp_dir().join(format!(
            "vkarmani-log-test-{}-{}.txt",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(
            &path,
            format!("{}\nlast Unicode Я\nkey=synthetic\n", "Я".repeat(100000)),
        )
        .unwrap();
        let tail = bounded_log_tail(&path, 2).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0], "last Unicode Я");
        assert!(!tail[1].contains("synthetic"));
        fs::remove_file(&path).unwrap();
        assert!(bounded_log_tail(&path, 200).unwrap().is_empty());
    }
    #[test]
    fn repeated_links_at_remote_body_limit_redact_in_bounded_time() {
        let input = "prefix VLESS://synthetic-token@invalid.example:443 Я\n".repeat(42000);
        let started = Instant::now();
        let output = redact_sensitive(&input);
        assert!(!output.contains("synthetic-token"));
        assert!(output.contains("Я"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn log_lease_blocks_replacement_and_write_failures_preserve_bytes() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("vkarmani-log-lease-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("log.txt");
        ensure_log_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"");
        append_bounded_log(&path, "preserve Я").unwrap();
        let original = fs::read(&path).unwrap();
        {
            let lease = open_safe_log(&path, false).unwrap().unwrap();
            assert!(fs::remove_file(&path).is_err());
            assert!(fs::rename(&dir, dir.with_extension("replaced")).is_err());
            assert_eq!(lease.file.metadata().unwrap().len(), original.len() as u64);
        }
        {
            let _exclusive = OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&path)
                .unwrap();
            assert!(reset_bounded_log(&path).is_err());
            assert!(append_bounded_log(&path, "unsafe").is_err());
            assert!(bounded_log_tail(&path, 1).is_err());
        }
        let original_permissions = fs::metadata(&path).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions.clone()).unwrap();
        assert!(reset_bounded_log(&path).is_err());
        assert!(ensure_log_file(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::set_permissions(&path, original_permissions).unwrap();
        reset_bounded_log(&path).unwrap();
        assert!(bounded_log_tail(&path, 1).unwrap().is_empty());
        fs::remove_file(&path).unwrap();
        let target = dir.join("target.txt");
        fs::write(&target, b"foreign").unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(reset_bounded_log(&path).is_err());
        assert!(ensure_log_file(&path).is_err());
        assert!(bounded_log_tail(&path, 1).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"foreign");
        fs::remove_file(path).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn junction_log_parent_rejects_all_sinks_and_directory_creation() {
        let _fixture = HELPER_TEST_LOCK.lock().unwrap();
        let dir =
            std::env::temp_dir().join(format!("vkarmani-log-junction-{}", std::process::id()));
        let target = dir.join("target");
        let link = dir.join("link");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("log.txt"), b"foreign").unwrap();
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
        run_command_with_timeout(command, Duration::from_secs(3), "synthetic log junction")
            .unwrap();
        let path = link.join("log.txt");
        assert!(append_bounded_log(&path, "unsafe").is_err());
        assert!(reset_bounded_log(&path).is_err());
        assert!(ensure_log_file(&path).is_err());
        assert!(bounded_log_tail(&path, 1).is_err());
        assert!(ensure_safe_log_directory(&link.join("missing-child")).is_err());
        assert!(!target.join("missing-child").exists());
        assert_eq!(fs::read(target.join("log.txt")).unwrap(), b"foreign");
        let symlink = dir.join("symlink.txt");
        match std::os::windows::fs::symlink_file(target.join("log.txt"), &symlink) {
            Ok(()) => {
                assert!(reset_bounded_log(&symlink).is_err());
                assert!(bounded_log_tail(&symlink, 1).is_err());
                assert!(ensure_log_file(&symlink).is_err());
                fs::remove_file(symlink).unwrap();
            }
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("LOG_SYMLINK_NOT_RUN: host privilege unavailable")
            }
            Err(error) => panic!("synthetic symlink creation: {error}"),
        }
        assert_eq!(fs::read(target.join("log.txt")).unwrap(), b"foreign");
        fs::remove_dir(link).unwrap();
        fs::remove_file(target.join("log.txt")).unwrap();
        fs::remove_dir(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
