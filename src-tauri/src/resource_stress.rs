//! Synthetic, owned helper stress. Run separately with --ignored --nocapture
//! --test-threads=1; this is not a native VPN or duration-soak acceptance test.
use super::*;
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::ToolHelp::*, ProcessStatus::*, Threading::*},
};
fn sample() -> Value {
    unsafe {
        let process = GetCurrentProcess();
        let mut handles = 0;
        assert_ne!(GetProcessHandleCount(process, &mut handles), 0);
        let mut memory: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
        memory.cb = std::mem::size_of_val(&memory) as u32;
        assert_ne!(
            GetProcessMemoryInfo(
                process,
                (&mut memory as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
                memory.cb
            ),
            0
        );
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of_val(&entry) as u32;
        let mut threads = 0;
        let mut valid = Thread32First(snapshot, &mut entry);
        while valid != 0 {
            if entry.th32OwnerProcessID == std::process::id() {
                threads += 1;
            }
            valid = Thread32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        let (mut create, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
            std::mem::zeroed();
        assert_ne!(
            GetProcessTimes(process, &mut create, &mut exit, &mut kernel, &mut user),
            0
        );
        let ticks = |v: FILETIME| ((v.dwHighDateTime as u64) << 32) | v.dwLowDateTime as u64;
        json!({"handles":handles,"threads":threads,"workingSetBytes":memory.WorkingSetSize,"privateBytes":memory.PrivateUsage,"cpuSeconds":(ticks(kernel)+ticks(user)) as f64/10000000.0})
    }
}
fn cycle() {
    let mut command = Command::new(system_program("powershell").unwrap());
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[Console]::Out.Write('synthetic'); [Console]::Error.Write('owned')",
    ]);
    let result =
        run_command_with_timeout(command, Duration::from_secs(5), "owned resource stress").unwrap();
    assert!(result.contains("synthetic"));
}
#[test]
#[ignore = "measured separate 100-cycle Windows stress; no live VPN"]
fn measured_owned_helper_stress() {
    for _ in 0..5 {
        cycle();
    }
    std::thread::sleep(Duration::from_millis(200));
    let before = sample();
    let started = Instant::now();
    let mut peak = before.clone();
    for _ in 0..100 {
        cycle();
        let current = sample();
        for key in ["handles", "threads", "workingSetBytes", "privateBytes"] {
            if current[key].as_u64().unwrap() > peak[key].as_u64().unwrap() {
                peak[key] = current[key].clone();
            }
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    let after = sample();
    println!(
        "RESOURCE_STRESS {}",
        json!({"cycles":100,"warmupCycles":5,"durationSeconds":started.elapsed().as_secs_f64(),"before":before,"peak":peak,"after":after,"scope":"synthetic owned helpers; caller CPU excludes child CPU"})
    );
    assert!(
        after["handles"].as_u64().unwrap() <= before["handles"].as_u64().unwrap() + 4,
        "handle growth"
    );
    assert!(
        after["threads"].as_u64().unwrap() <= before["threads"].as_u64().unwrap() + 1,
        "thread growth"
    );
    assert!(
        after["privateBytes"].as_u64().unwrap()
            <= before["privateBytes"].as_u64().unwrap() + 16 * 1024 * 1024,
        "private byte growth"
    );
}
