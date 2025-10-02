/// System process creation utilities
///
/// This module provides functionality to create Windows PPL processes,
/// which are required to launch system tools with elevated privileges.

use anyhow::{Context, Result};
use windows::{
    Win32::Foundation::{HANDLE, CloseHandle, GetLastError, WIN32_ERROR},
    Win32::System::Threading::{
        CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
        DeleteProcThreadAttributeList, STARTUPINFOEXW, PROCESS_INFORMATION,
        EXTENDED_STARTUPINFO_PRESENT, CREATE_PROTECTED_PROCESS, PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, GetProcessInformation, ProcessProtectionLevelInfo,
        LPPROC_THREAD_ATTRIBUTE_LIST
    },
};

/// Represents process protection level information from Windows API
#[repr(C)]
struct ProcessProtectionLevelInformation {
    protection_level: u32,
}

/// System Executor - manages creation of protected system processes
pub struct SystemExecutor {
    process_handle: Option<HANDLE>,
    thread_handle: Option<HANDLE>,
}

impl SystemExecutor {
    /// Create a new system executor
    pub fn new() -> Self {
        Self {
            process_handle: None,
            thread_handle: None,
        }
    }

    /// Get the protection level of a running process
    pub fn get_protection_level(&self, process_id: u32) -> u32 {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) {
                let mut protection_info = ProcessProtectionLevelInformation { protection_level: 0 };

                if GetProcessInformation(
                    handle,
                    ProcessProtectionLevelInfo,
                    &mut protection_info as *mut _ as *mut _,
                    std::mem::size_of::<ProcessProtectionLevelInformation>() as u32
                ).is_ok() {
                    let _ = CloseHandle(handle);
                    return protection_info.protection_level;
                }

                let _ = CloseHandle(handle);
            }
        }
        0
    }


    /// Create a new WinTCB protected process
    ///
    /// # Arguments
    /// * `_protection_level` - Ignored, always uses WinTCB (0)
    /// * `command_line` - Full command line to execute
    ///
    /// # Returns
    /// Process ID of the created protected process
    pub fn create_protected_process(&mut self, _protection_level: u32, command_line: &str) -> Result<u32> {
        unsafe {
            // Step 1: Initialize WinTCB attributes
            let (ptal, _buffer) = self.initialize_wintcb_attributes()
                .context("Failed to initialize WinTCB attributes")?;

            // Step 2: Prepare process creation structures
            let mut siex = STARTUPINFOEXW::default();
            siex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            siex.lpAttributeList = ptal;

            let mut pi = PROCESS_INFORMATION::default();

            // Step 3: Convert command line to wide string
            let mut cmd_line: Vec<u16> = command_line.encode_utf16().chain(std::iter::once(0)).collect();

            // Step 4: Create the protected process
            let result = CreateProcessW(
                None,                                               // Application name
                Some(windows::core::PWSTR(cmd_line.as_mut_ptr())), // Command line
                None,                                               // Process security attributes
                None,                                               // Thread security attributes
                true,                                               // Inherit handles
                EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS, // Creation flags
                None,                                               // Environment
                None,                                               // Current directory
                &siex.StartupInfo,                                  // Startup info
                &mut pi                                             // Process information
            );

            // Step 5: Cleanup attribute list
            DeleteProcThreadAttributeList(ptal);
            // _buffer will be automatically dropped by Rust

            // Step 6: Handle result
            if result.is_err() {
                anyhow::bail!("CreateProcessW failed: {:?}", GetLastError());
            }

            // Step 7: Store handles and return process ID
            self.process_handle = Some(pi.hProcess);
            self.thread_handle = Some(pi.hThread);

            let process_id = pi.dwProcessId;
            println!("Successfully created protected process with PID: {}", process_id);

            println!("Protection level: WinTCB ({})", self.get_protection_level(process_id));

            Ok(process_id)
        }
    }

    /// Initialize process thread attribute list with WinTCB protection
    fn initialize_wintcb_attributes(&self) -> Result<(LPPROC_THREAD_ATTRIBUTE_LIST, Vec<u8>)> {
        unsafe {
            let mut size = 0usize;

            // Get required size for attribute list
            let result = InitializeProcThreadAttributeList(None, 1, Some(0), &mut size);
            if result.is_err() && GetLastError() != WIN32_ERROR(122) { // ERROR_INSUFFICIENT_BUFFER
                anyhow::bail!("Failed to get attribute list size: {:?}", GetLastError());
            }

            // Allocate buffer using Vec<u8>
            let mut buffer = vec![0u8; size];
            let ptal = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr() as *mut _);

            // Initialize the attribute list
            if InitializeProcThreadAttributeList(Some(ptal), 1, Some(0), &mut size).is_err() {
                anyhow::bail!("InitializeProcThreadAttributeList failed: {:?}", GetLastError());
            }

            // Set WinTCB protection level (0)
            let protection_level: u32 = 0; // WinTCB
            if UpdateProcThreadAttribute(
                ptal,
                0,
                PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL.try_into().unwrap(),
                Some(&protection_level as *const _ as *const _),
                std::mem::size_of::<u32>(),
                None,
                None
            ).is_err() {
                DeleteProcThreadAttributeList(ptal);
                anyhow::bail!("UpdateProcThreadAttribute failed: {:?}", GetLastError());
            }

            Ok((ptal, buffer))
        }
    }

}

impl Drop for SystemExecutor {
    fn drop(&mut self) {
        unsafe {
            if let Some(handle) = self.process_handle {
                let _ = CloseHandle(handle);
            }
            if let Some(handle) = self.thread_handle {
                let _ = CloseHandle(handle);
            }
        }
    }
}