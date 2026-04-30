use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr::{null, null_mut},
    slice,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

#[cfg(target_os = "windows")]
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(target_os = "windows")]
#[link(name = "Crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        data_in: *mut DataBlob,
        data_description: *const u16,
        optional_entropy: *mut DataBlob,
        reserved: *mut core::ffi::c_void,
        prompt_struct: *mut core::ffi::c_void,
        flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;

    fn CryptUnprotectData(
        data_in: *mut DataBlob,
        data_description: *mut *mut u16,
        optional_entropy: *mut DataBlob,
        reserved: *mut core::ffi::c_void,
        prompt_struct: *mut core::ffi::c_void,
        flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};


mod platform;
pub(crate) use platform::*;
mod state;
pub(crate) use state::*;
mod core_paths;
pub(crate) use core_paths::*;
mod xray_config;
pub(crate) use xray_config::*;
mod runtime_lifecycle;
pub(crate) use runtime_lifecycle::*;
mod runtime_status;
pub(crate) use runtime_status::*;
mod remote_fetch;
pub(crate) use remote_fetch::*;
mod commands;
pub(crate) use commands::*;
mod app_run;
pub use app_run::run;
pub(crate) use app_run::refresh_tray_menu;
#[cfg(test)]
mod tests;
