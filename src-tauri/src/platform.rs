use super::*;

pub(crate) const SOCKS_PORT: u16 = 10808;
pub(crate) const HTTP_PORT: u16 = 10809;
pub(crate) const XRAY_API_PORT: u16 = 10810;
pub(crate) const MAX_REMOTE_FETCH_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_REMOTE_FETCH_REDIRECTS: usize = 3;
pub(crate) const PROXY_BYPASS: &str = "<local>";
pub(crate) const IPIFY_URL: &str = "https://api.ipify.org?format=json";
pub(crate) const APP_USER_AGENT: &str = concat!("VKarmani-Desktop/", env!("CARGO_PKG_VERSION"));
#[cfg(all(target_os = "windows", not(debug_assertions)))]
pub(crate) const STARTUP_REGISTRY_VALUE: &str = "VKarmani Desktop";
pub(crate) const TUN_INTERFACE_NAME: &str = "vkarmani-tun";

#[cfg(target_os = "windows")]
pub(crate) fn hide_child_console(command: &mut Command) {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn hide_child_console(_command: &mut Command) {}

#[cfg(target_os = "windows")]
pub(crate) fn system_program(name: &str) -> Result<PathBuf, String> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("SYSTEM_DIRECTORY_UNAVAILABLE".into());
    }
    if !matches!(name, "powershell" | "reg" | "ping" | "wmic" | "tasklist") {
        return Err("SYSTEM_PROGRAM_UNSUPPORTED".into());
    }
    let root = PathBuf::from(String::from_utf16_lossy(&buffer[..length]));
    Ok(match name {
        "powershell" => root.join("WindowsPowerShell/v1.0/powershell.exe"),
        "wmic" => root.join("wbem/wmic.exe"),
        other => root.join(format!("{other}.exe")),
    })
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn system_program(_name: &str) -> Result<PathBuf, String> {
    Err("WINDOWS_SYSTEM_PROGRAM_REQUIRED".into())
}
