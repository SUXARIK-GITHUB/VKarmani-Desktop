use super::*;
use std::cell::RefCell;
#[test]
fn malformed_duplicate_and_foreign_handoff_arguments_fail_closed() {
    let good = format!("{PREFIX}123:456:{}", "a".repeat(48));
    let args = vec!["app.exe".into(), good.clone()];
    assert_eq!(parse(&args).unwrap().unwrap().pid, 123);
    assert!(parse(&["app.exe".into()]).unwrap().is_none());
    for value in [
        PREFIX.into(),
        "--vkarmani-elevate-handoff".into(),
        format!("{PREFIX}0:1:{}", "a".repeat(48)),
        format!("{PREFIX}1:0:{}", "a".repeat(48)),
        format!("{PREFIX}4294967296:1:{}", "a".repeat(48)),
        format!("{PREFIX}1:1:{}", "z".repeat(48)),
        format!("{PREFIX}1:1:{}", "a".repeat(49)),
        format!("{PREFIX}1:1:{}:", "a".repeat(48)),
    ] {
        assert!(parse(&["app.exe".into(), value]).is_err());
    }
    assert!(parse(&["app.exe".into(), good.clone(), good]).is_err());
}
#[test]
fn consumed_handoff_is_removed_from_official_restart_but_normal_args_remain() {
    let args = vec![
        "app.exe".into(),
        "--safe-mode".into(),
        format!("{PREFIX}1:2:{}", "a".repeat(48)).into(),
        "Unicode путь".into(),
    ];
    let filtered = filtered(args);
    assert_eq!(
        filtered,
        vec![
            std::ffi::OsString::from("app.exe"),
            "--safe-mode".into(),
            "Unicode путь".into()
        ]
    );
}
#[test]
fn windows_quoting_retains_spaces_quotes_backslashes_unicode_and_rejects_nul() {
    for (input, expected) in [
        ("", "\"\""),
        ("a b", "\"a b\""),
        ("a\\", "\"a\\\\\""),
        ("a\"b", "\"a\\\"b\""),
        ("путь", "\"путь\""),
    ] {
        assert_eq!(quote_arg(input).unwrap(), expected);
    }
    assert!(quote_arg("bad\0arg").is_err());
}
#[cfg(windows)]
#[test]
fn actual_windows_argument_parser_roundtrips_generated_values_without_shell_execution() {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
    let values = [
        "",
        "app name",
        "a\"b",
        "end\\",
        "\\\\quoted\\\"x",
        "Юникод 🚀",
        "& whoami | > file",
        "line\nvalue",
    ];
    for left in values {
        for right in values {
            let command = format!(
                "app.exe {} {}",
                quote_arg(left).unwrap(),
                quote_arg(right).unwrap()
            );
            let wide = command.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut count = 0;
            let args = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
            assert!(!args.is_null());
            let got = (0..count as usize)
                .map(|i| {
                    let ptr = unsafe { *args.add(i) };
                    let mut size = 0;
                    while unsafe { *ptr.add(size) } != 0 {
                        size += 1;
                    }
                    std::ffi::OsString::from_wide(unsafe { slice::from_raw_parts(ptr, size) })
                })
                .collect::<Vec<_>>();
            unsafe {
                crate::LocalFree(args.cast());
            }
            assert_eq!(
                got,
                vec![
                    std::ffi::OsString::from("app.exe"),
                    left.into(),
                    right.into()
                ]
            );
        }
    }
}
#[cfg(windows)]
#[test]
fn windows_wait_accepts_committed_grant_even_when_parent_already_exited() {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    // Unnamed events model scheduling only. No process is launched/elevated,
    // and no live parent, AppData, registry or network is accessed.
    struct Event(HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let event = || {
        let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!handle.is_null());
        Event(handle)
    };
    let cancel = event();
    let go = event();
    let parent_exit = event();
    let handles = handoff_wait_handles(cancel.0, go.0, parent_exit.0);
    assert_eq!(
        unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, 0) },
        WAIT_TIMEOUT
    );
    unsafe {
        SetEvent(parent_exit.0);
    }
    assert_eq!(
        unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, 0) },
        WAIT_OBJECT_0 + 2
    );
    unsafe {
        SetEvent(go.0);
    }
    assert_eq!(
        unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, 0) },
        WAIT_OBJECT_0 + 1
    );
    unsafe {
        SetEvent(cancel.0);
    }
    assert_eq!(
        unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, 0) },
        WAIT_OBJECT_0
    );
}
struct Fake<'a> {
    calls: &'a RefCell<Vec<&'static str>>,
    fail: Option<&'static str>,
    consent: bool,
}
impl Backend for Fake<'_> {
    fn request(&mut self) -> Result<bool, ElevationError> {
        self.calls.borrow_mut().push("uac-request");
        if self.fail == Some("request") {
            return Err(failure("ELEVATION_LAUNCH_FAILED"));
        }
        Ok(self.consent)
    }
    fn ready(&mut self) -> Result<(), ElevationError> {
        self.calls.borrow_mut().push("child-ready-before-builder");
        if self.fail == Some("ready") {
            return Err(failure("ELEVATION_CHILD_UNAVAILABLE"));
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<(), ElevationError> {
        self.calls.borrow_mut().push("owned-cleanup");
        if self.fail == Some("cleanup") {
            return Err(failure("ELEVATION_CLEANUP_UNCONFIRMED"));
        }
        Ok(())
    }
    fn commit(&mut self) -> Result<(), ElevationError> {
        self.calls
            .borrow_mut()
            .push("permit-child-to-wait-parent-exit");
        if self.fail == Some("commit") {
            return Err(failure("ELEVATION_EVENT_FAILED"));
        }
        Ok(())
    }
    fn exit(&mut self) {
        self.calls.borrow_mut().push("approved-parent-exit");
    }
}
#[test]
fn cancelled_uac_never_disconnects_closes_or_releases_parent() {
    let calls = RefCell::new(vec![]);
    assert!(!transaction(&mut Fake {
        calls: &calls,
        fail: None,
        consent: false
    })
    .unwrap());
    assert_eq!(*calls.borrow(), ["uac-request"]);
}
#[test]
fn launch_or_child_ready_failure_preserves_parent_without_cleanup() {
    for fail in ["request", "ready"] {
        let calls = RefCell::new(vec![]);
        assert!(transaction(&mut Fake {
            calls: &calls,
            fail: Some(fail),
            consent: true
        })
        .is_err());
        assert!(!calls.borrow().contains(&"owned-cleanup"));
        assert!(!calls.borrow().contains(&"approved-parent-exit"));
    }
}
#[test]
fn cleanup_or_grant_failure_cannot_approve_parent_exit() {
    for fail in ["cleanup", "commit"] {
        let calls = RefCell::new(vec![]);
        assert!(transaction(&mut Fake {
            calls: &calls,
            fail: Some(fail),
            consent: true
        })
        .is_err());
        assert!(!calls.borrow().contains(&"approved-parent-exit"));
        if fail == "cleanup" {
            assert!(!calls.borrow().contains(&"permit-child-to-wait-parent-exit"));
        }
    }
}
#[test]
fn success_orders_child_preparation_cleanup_commit_and_parent_exit() {
    let calls = RefCell::new(vec![]);
    assert!(transaction(&mut Fake {
        calls: &calls,
        fail: None,
        consent: true
    })
    .unwrap());
    assert_eq!(
        *calls.borrow(),
        [
            "uac-request",
            "child-ready-before-builder",
            "owned-cleanup",
            "permit-child-to-wait-parent-exit",
            "approved-parent-exit"
        ]
    );
}
