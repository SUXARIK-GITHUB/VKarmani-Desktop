use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "windows")]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide = |path: &Path| -> std::io::Result<Vec<u16>> {
        let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
        if text.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NUL path",
            ));
        }
        text.push(0);
        Ok(text)
    };
    let src = wide(source)?;
    let dst = wide(destination)?;
    // One same-directory rename with replacement/write-through, never the
    // old delete-then-rename fallback. The new file inherits its owned state
    // directory ACL. ReplaceFileW without a recovery backup can lose the old
    // filename on ERROR_UNABLE_TO_MOVE_REPLACEMENT; do not use that sequence.
    let ok = unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), 0x1 | 0x8) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn state_path_error(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

pub(crate) fn state_directory_guards(directory: &Path, create: bool) -> std::io::Result<Vec<File>> {
    if !directory.is_absolute()
        || directory
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(state_path_error("STATE_PATH_INVALID"));
    }
    let mut parents = directory.ancestors().collect::<Vec<_>>();
    parents.reverse();
    let mut guards = Vec::new();
    for parent in parents {
        let metadata = match fs::symlink_metadata(parent) {
            Ok(metadata) => metadata,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(parent)?;
                fs::symlink_metadata(parent)?
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(state_path_error("STATE_DIRECTORY_REPARSE_OR_TYPE"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            use windows_sys::Win32::Storage::FileSystem::*;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(state_path_error("STATE_DIRECTORY_REPARSE_OR_TYPE"));
            }
            let handle = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(parent)?;
            if handle.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(state_path_error("STATE_DIRECTORY_REPARSE_OR_TYPE"));
            }
            guards.push(handle);
        }
    }
    Ok(guards)
}

#[cfg(test)]
pub(crate) fn ensure_state_directory(directory: &Path) -> Result<(), String> {
    state_directory_guards(directory, true)
        .map(|_| ())
        .map_err(|error| format!("STATE_DIRECTORY: {error}"))
}

pub(crate) fn check_state_file(file: &File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(state_path_error("STATE_FILE_TYPE"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::*;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(state_path_error("STATE_FILE_REPARSE"));
        }
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if information.nNumberOfLinks != 1 {
            return Err(state_path_error("STATE_FILE_HARDLINK"));
        }
    }
    Ok(())
}

fn existing_state_target(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(state_path_error("STATE_FILE_REPARSE_OR_TYPE"))
        }
        Ok(_) => {}
    }
    let mut options = OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(windows))]
    options.read(true);
    check_state_file(&options.open(path)?)
}

pub(crate) fn read_state_file(path: &Path, maximum: u64) -> std::io::Result<Option<String>> {
    read_state_bytes(path, maximum)?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "STATE_INVALID_UTF8")
            })
        })
        .transpose()
}

pub(crate) fn read_state_bytes(path: &Path, maximum: u64) -> std::io::Result<Option<Vec<u8>>> {
    let parent = path
        .parent()
        .ok_or_else(|| state_path_error("STATE_PATH_INVALID"))?;
    let _parents = match state_directory_guards(parent, false) {
        Ok(guards) => guards,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    check_state_file(&file)?;
    if file.metadata()?.len() > maximum {
        return Err(state_path_error("STATE_TOO_LARGE"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(state_path_error("STATE_TOO_LARGE"));
    }
    Ok(Some(bytes))
}

#[cfg(windows)]
fn temporary_replace_conflict(error: &std::io::Error, destination: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    if matches!(error.raw_os_error(), Some(32 | 33)) {
        return true;
    }
    // MoveFileEx can report ACCESS_DENIED even for a delete-sharing reader.
    // An exclusive DELETE-access probe detects that reader too. Retry only
    // when the probe confirms a sharing conflict, not for generic denial;
    // ordinary ACL/read-only failures are not converted into transient errors.
    error.raw_os_error() == Some(5)
        && OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(destination)
            .is_err_and(|probe| matches!(probe.raw_os_error(), Some(32 | 33)))
}

#[cfg(windows)]
fn rename_access_currently_available(source: &Path, destination: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    let mut guards = Vec::new();
    for path in [source, destination] {
        let Ok(file) = OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        else {
            return false;
        };
        if check_state_file(&file).is_err()
            || !file.metadata().is_ok_and(|m| !m.permissions().readonly())
        {
            return false;
        }
        guards.push(file);
    }
    true
}

#[cfg(windows)]
fn replace_file_with_retry(
    temporary: &Path,
    destination: &Path,
    mut replace: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut rechecked_access = false;
    let mut result = replace(temporary, destination);
    for pause in [10, 20, 40, 80] {
        let Some(error) = result.as_ref().err() else {
            return result;
        };
        let sharing = temporary_replace_conflict(error, destination);
        // A reader can close between MoveFileExW's error5 and the sharing
        // probe. Permit ONE reattempt only after exclusive DELETE access to
        // both safe, non-readonly files is confirmed. Never retry arbitrary
        // access denial or extend the existing bounded retry budget.
        let available = !sharing
            && !rechecked_access
            && error.raw_os_error() == Some(5)
            && rename_access_currently_available(temporary, destination);
        if !sharing && !available {
            return result;
        }
        rechecked_access |= available;
        std::thread::sleep(Duration::from_millis(pause));
        existing_state_target(destination)?;
        result = replace(temporary, destination);
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
pub(crate) fn atomic_write_text(path: &Path, payload: &str, context: &str) -> Result<(), String> {
    atomic_write_state_text(path, payload)
        .map_err(|error| format!("{context}: atomic replacement: {error}"))
}

#[cfg(test)]
pub(crate) fn atomic_write_state_text(path: &Path, payload: &str) -> std::io::Result<()> {
    atomic_write_state_text_with_limit(path, payload, ENCRYPTED_STATE_MAX_BYTES)
}

pub(crate) fn atomic_write_state_text_with_limit(
    path: &Path,
    payload: &str,
    maximum: u64,
) -> std::io::Result<()> {
    if payload.len() as u64 > maximum {
        return Err(state_path_error("STATE_TOO_LARGE"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| state_path_error("STATE_PATH_INVALID"))?;
    let _parents = state_directory_guards(parent, true)?;
    existing_state_target(path)?;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or_default();
    let temporary = parent.join(format!(
        ".vkarmani-state-{}-{nonce}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        {
            replace_file_with_retry(&temporary, path, replace_file)
        }
        #[cfg(not(windows))]
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        // This exact temporary file was created above by this invocation.
        // The old target is never explicitly removed, even on replace failure.
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_targets_reject_traversal_directories_and_hard_links() {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-state-path-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let original = dir.join("original.json");
        let linked = dir.join("linked.json");
        fs::write(&original, "synthetic-original").unwrap();
        fs::hard_link(&original, &linked).unwrap();
        #[cfg(windows)]
        {
            assert!(atomic_write_state_text(&linked, "bad").is_err());
            assert!(read_state_file(&linked, 1024).is_err());
        }
        assert!(atomic_write_state_text(&dir, "bad").is_err());
        assert!(
            atomic_write_state_text(&dir.join("..").join("must-not-be-created.json"), "bad")
                .is_err()
        );
        assert_eq!(fs::read_to_string(&original).unwrap(), "synthetic-original");
        fs::remove_file(&linked).unwrap();
        fs::remove_file(&original).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn junction_state_parent_rejects_reads_writes_and_child_creation() {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-state-junction-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let target = dir.join("target");
        let link = dir.join("link");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("state.json"), "synthetic-foreign").unwrap();
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
        run_command_with_timeout(command, Duration::from_secs(3), "synthetic state junction")
            .unwrap();
        assert!(read_state_file(&link.join("state.json"), 1024).is_err());
        assert!(atomic_write_state_text(&link.join("state.json"), "bad").is_err());
        assert!(ensure_state_directory(&link.join("missing-child")).is_err());
        assert!(!target.join("missing-child").exists());
        assert_eq!(
            fs::read_to_string(target.join("state.json")).unwrap(),
            "synthetic-foreign"
        );
        fs::remove_dir(link).unwrap();
        fs::remove_file(target.join("state.json")).unwrap();
        fs::remove_dir(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn directory_guard_pins_parent_and_access_denial_is_not_a_sharing_retry() {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-state-pin-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        fs::write(&path, "original").unwrap();
        let guards = state_directory_guards(&dir, false).unwrap();
        assert!(fs::rename(&dir, dir.with_extension("moved")).is_err());
        let original_permissions = fs::metadata(&path).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(!temporary_replace_conflict(
            &std::io::Error::from_raw_os_error(5),
            &path
        ));
        assert!(atomic_write_state_text(&path, "bad").is_err());
        fs::set_permissions(&path, original_permissions).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        drop(guards);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
    #[test]
    #[cfg(target_os = "windows")]
    fn transient_delete_share_lock_recovers_without_losing_the_old_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-state-sharing-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let target = dir.join("synthetic.json");
        atomic_write_text(&target, "old", "test").unwrap();
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&target)
            .unwrap();
        let result = std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                drop(blocker);
            });
            atomic_write_text(&target, "new", "test")
        });
        let actual = fs::read_to_string(&target).unwrap();
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&dir).unwrap();
        assert!(
            result.is_ok(),
            "a short transient sharing lock must be recoverable: {result:?}"
        );
        assert_eq!(actual, "new");
    }
    #[test]
    fn state_replacement_and_failure_leave_last_good_target_intact() {
        let dir = std::env::temp_dir().join(format!(
            "vkarmani-state-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let target = dir.join("synthetic.json");
        atomic_write_text(&target, "old", "test").unwrap();
        atomic_write_text(&target, "new", "test").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        let locked = OpenOptions::new().read(true).open(&target).unwrap();
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let no_delete_share = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&target)
                .unwrap();
            assert!(atomic_write_text(&target, "must-not-replace", "test").is_err());
            assert_eq!(fs::read_to_string(&target).unwrap(), "new");
            drop(no_delete_share);
        }
        drop(locked);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1); // no partial temp remains
        fs::remove_file(target).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn competing_handles_classify_preflight_and_replace_conflicts_without_data_loss() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        // Both layouts must be isolated. Shared global Temp is an uncontrolled
        // namespace (the full-suite failure occurred before our first reader).
        // Preserve that failure as evidence, not as a deterministic lock test.
        let root = std::env::temp_dir().join(format!(
            "vkarmani-sharing-isolated-{}-{}",
            std::process::id(),
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        for dedicated in [false, true] {
            for iteration in 0..12 {
                let name = format!(
                    "vkarmani-sharing-matrix-{}-{}-{iteration}",
                    std::process::id(),
                    crate::compat_storage::durable::random_state_id().unwrap()
                );
                let parent = if dedicated {
                    let p = root.join(&name);
                    fs::create_dir(&p).unwrap();
                    p
                } else {
                    root.clone()
                };
                let target = parent.join(if dedicated {
                    "owned-tun-routes-v1.dpapi".into()
                } else {
                    format!("{name}.dpapi")
                });
                atomic_write_state_text(&target, "old").unwrap();
                // MoveFileEx on this Windows cannot replace an open target,
                // even when the reader grants FILE_SHARE_DELETE.
                let reader = OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .open(&target)
                    .unwrap();
                let error = atomic_write_state_text(&target, "must-not-write").unwrap_err();
                assert!(
                    temporary_replace_conflict(&error, &target),
                    "cooperative reader conflict: {error:?}"
                );
                drop(reader);
                assert_eq!(fs::read_to_string(&target).unwrap(), "old");
                atomic_write_state_text(&target, "new").unwrap();
                // Observe the actual stage rather than infer it from the
                // public wrapper, which labels every IO failure replacement.
                let exclusive = OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(&target)
                    .unwrap();
                let preflight = existing_state_target(&target);
                let error = atomic_write_state_text(&target, "must-not-write").unwrap_err();
                assert!(
                    temporary_replace_conflict(&error, &target),
                    "exclusive conflict: {error:?}"
                );
                println!("SHARING_STAGE dedicated={dedicated} iteration={iteration} target_probe={preflight:?} writer={error:?}");
                drop(exclusive);
                assert_eq!(fs::read_to_string(&target).unwrap(), "new");
                // Read sharing allows validation but denies rename/delete.
                let blocker = OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ)
                    .open(&target)
                    .unwrap();
                existing_state_target(&target).unwrap();
                let error = atomic_write_state_text(&target, "must-not-replace").unwrap_err();
                assert!(
                    temporary_replace_conflict(&error, &target),
                    "replace stage: {error:?}"
                );
                drop(blocker);
                assert_eq!(fs::read_to_string(&target).unwrap(), "new");
                atomic_write_state_text(&target, "recovered").unwrap();
                assert_eq!(fs::read_to_string(&target).unwrap(), "recovered");
                assert_eq!(fs::read_dir(&parent).unwrap().count(), 1);
                fs::remove_file(target).unwrap();
                if dedicated {
                    fs::remove_dir(parent).unwrap();
                }
            }
        }
        fs::remove_dir(root).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn transient_cooperative_reader_is_a_retryable_replace_conflict() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        for _ in 0..12 {
            let directory = std::env::temp_dir().join(format!(
                "vkarmani-cooperative-reader-{}-{}",
                std::process::id(),
                crate::compat_storage::durable::random_state_id().unwrap()
            ));
            fs::create_dir(&directory).unwrap();
            let runtime_pins =
                lock_runtime_parent_paths(&directory.join("synthetic-config.json")).unwrap();
            let target = directory.join("owned-tun-routes-v1.dpapi");
            atomic_write_state_text(&target, "old").unwrap();
            let reader = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&target)
                .unwrap();
            let temporary = directory.join("synthetic-new.tmp");
            fs::write(&temporary, "new").unwrap();
            let mut reader = Some(reader);
            let mut attempts = 0;
            // Release at the precise failing boundary, on the writer thread.
            // A sleep in a sibling thread does not establish a short hold
            // under CI load and misses the post-failure-probe race.
            let result = replace_file_with_retry(&temporary, &target, |source, destination| {
                attempts += 1;
                let result = replace_file(source, destination);
                if reader.is_some() {
                    assert_eq!(
                        result.as_ref().err().and_then(|e| e.raw_os_error()),
                        Some(5)
                    );
                    drop(reader.take());
                }
                result
            });
            let actual = fs::read_to_string(&target).unwrap();
            fs::remove_file(target).unwrap();
            drop(runtime_pins);
            fs::remove_dir(directory).unwrap();
            assert!(
                result.is_ok(),
                "a short cooperative reader must recover: {result:?}"
            );
            assert_eq!(actual, "new");
            assert_eq!(attempts, 2);
            assert!(!temporary.exists());
        }
    }
    #[test]
    #[cfg(windows)]
    fn access_recheck_is_safe_bounded_and_never_becomes_generic_denial_retry() {
        let directory = std::env::temp_dir().join(format!(
            "vkarmani-recheck-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&directory).unwrap();
        let target = directory.join("old.dpapi");
        let temporary = directory.join("new.tmp");
        fs::write(&target, "old").unwrap();
        fs::write(&temporary, "new").unwrap();
        assert!(rename_access_currently_available(&temporary, &target));
        let mut attempts = 0;
        let result = replace_file_with_retry(&temporary, &target, |_, _| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(5))
        });
        assert_eq!(attempts, 2);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(5));
        assert_eq!(fs::read_to_string(&target).unwrap(), "old");
        assert_eq!(fs::read_to_string(&temporary).unwrap(), "new");
        let linked = directory.join("linked.dpapi");
        fs::hard_link(&target, &linked).unwrap();
        assert!(!rename_access_currently_available(&temporary, &target));
        fs::remove_file(linked).unwrap();
        let original_permissions = fs::metadata(&target).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&target, permissions.clone()).unwrap();
        assert!(!rename_access_currently_available(&temporary, &target));
        attempts = 0;
        let result = replace_file_with_retry(&temporary, &target, |source, destination| {
            attempts += 1;
            replace_file(source, destination)
        });
        assert_eq!(attempts, 1);
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "old");
        fs::set_permissions(&target, original_permissions).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_file(temporary).unwrap();
        fs::remove_dir(directory).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn permanent_reader_keeps_original_and_the_existing_five_attempt_limit() {
        use std::os::windows::fs::OpenOptionsExt;
        let directory = std::env::temp_dir().join(format!(
            "vkarmani-bounded-sharing-{}",
            crate::compat_storage::durable::random_state_id().unwrap()
        ));
        fs::create_dir(&directory).unwrap();
        let target = directory.join("old.dpapi");
        let temporary = directory.join("new.tmp");
        fs::write(&target, "old").unwrap();
        fs::write(&temporary, "new").unwrap();
        let reader = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&target)
            .unwrap();
        let mut attempts = 0;
        let result = replace_file_with_retry(&temporary, &target, |source, destination| {
            attempts += 1;
            replace_file(source, destination)
        });
        assert_eq!(attempts, 5);
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "old");
        drop(reader);
        fs::remove_file(target).unwrap();
        fs::remove_file(temporary).unwrap();
        fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn dpapi_round_trip_rejects_corruption_without_plaintext_fallback() {
        #[cfg(target_os = "windows")]
        {
            let secret = "synthetic-credential Россия 🌍";
            let encrypted = encrypt_access_key(secret).unwrap();
            assert!(!encrypted.contains(secret));
            assert_eq!(decrypt_access_key(&encrypted).unwrap(), secret);
            let mut bytes = general_purpose::STANDARD.decode(encrypted).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x80;
            assert!(decrypt_access_key(&general_purpose::STANDARD.encode(bytes)).is_err());
            assert!(decrypt_access_key("not-base64!").is_err());
        }
    }
    #[test]
    fn large_unicode_dpapi_payload_exceeds_old_ciphertext_limit_without_truncation() {
        #[cfg(target_os = "windows")]
        {
            let plaintext = "Россия 🌍".repeat(180_000);
            assert!(plaintext.len() > CLIENT_STATE_MAX_BYTES as usize);
            assert!(plaintext.len() < SENSITIVE_CLIENT_STATE_MAX_BYTES as usize);
            let encrypted = encrypt_access_key(&plaintext).unwrap();
            assert!(encrypted.len() > plaintext.len());
            assert!(encrypted.len() < ENCRYPTED_STATE_MAX_BYTES as usize);
            assert_eq!(decrypt_access_key(&encrypted).unwrap(), plaintext);
        }
    }
}
