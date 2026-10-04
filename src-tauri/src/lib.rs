use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr::{null, null_mut},
    slice,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
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
    fn GlobalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

mod runtime_integrity;
pub(crate) use runtime_integrity::*;
mod platform;
pub(crate) use platform::*;
mod state;
pub(crate) use state::*;
mod core_paths;
pub(crate) use core_paths::*;
mod xray_config;
pub(crate) use xray_config::*;
mod config_graph;
pub(crate) use config_graph::*;
mod runtime_lifecycle;
pub(crate) use runtime_lifecycle::*;
mod runtime_status;
pub(crate) use runtime_status::*;
mod runtime_operation;
pub(crate) use runtime_operation::*;
mod proxy_transaction;
pub(crate) use proxy_transaction::*;
mod owned_routes;
pub(crate) use owned_routes::*;
mod owned_process;
pub(crate) use owned_process::*;
mod app_policy;
pub(crate) use app_policy::*;
mod diagnostic_logs;
pub(crate) use diagnostic_logs::*;
mod bounded_command;
pub(crate) use bounded_command::*;
mod remote_fetch;
pub(crate) use remote_fetch::*;
mod commands;
pub(crate) use commands::*;
mod persistence;
pub(crate) use persistence::*;
mod subscription;
pub(crate) use subscription::*;
mod app_run;
pub(crate) use app_run::refresh_tray_menu;
pub use app_run::run;
#[cfg(all(test, target_os = "windows"))]
mod resource_stress;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) static HELPER_TEST_LOCK: Mutex<()> = Mutex::new(());
