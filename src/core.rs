/// Process manipulation utilities for Windows
///
/// This module provides functions for:
/// - Process thread enumeration and inspection
/// - Process suspension and termination
/// - System process information querying
/// - Handle conversion utilities

use windows::{
    core::{PCWSTR, PCSTR},
    Win32::Foundation::{HANDLE, CloseHandle, STATUS_INFO_LENGTH_MISMATCH, NTSTATUS},
    Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME},
    Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    Win32::System::WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION},
};

/// Thread state indicating the thread is waiting
const STATE_WAIT: u32 = 5;
/// Wait reason indicating the thread is suspended
const WAIT_REASON_SUSPENDED: u32 = 5;

/// Walk through the process list in system information buffer
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers and assumes
/// the buffer contains valid SYSTEM_PROCESS_INFORMATION structures.
///
/// # Arguments
/// * `buf` - Raw buffer containing process information
/// * `cb` - Callback function called for each process entry
unsafe fn walk_process_list<F: FnMut(*const SYSTEM_PROCESS_INFORMATION)>(mut buf: *mut u8, mut cb: F) {
    loop {
        let spi = buf as *const SYSTEM_PROCESS_INFORMATION;
        cb(spi);
        let next = unsafe { (*spi).NextEntryOffset };
        if next == 0 {
            break;
        }
        buf = unsafe { buf.add(next as usize) };
    }
}

/// Get the primary (first) thread ID for a given process
///
/// This function queries system process information to find the first thread
/// of the specified process, which is typically the main thread.
///
/// # Arguments
/// * `pid` - Process ID to search for
///
/// # Returns
/// * `Some(u32)` - Thread ID of the main thread if found
/// * `None` - If process not found or has no threads
pub fn get_primary_thread_id(pid: u32) -> Option<u32> {
    let mut buffer_size = 0x10000usize;

    loop {
        // Allocate buffer for system process information
        let mut buffer = vec![0u8; buffer_size];

        let status = unsafe {
            nt_query_system_process_information(buffer.as_mut_ptr() as *mut _, buffer_size as u32)
        };

        if status >= 0 { // NT_SUCCESS
            let mut thread_id: Option<u32> = None;

            unsafe {
                walk_process_list(buffer.as_mut_ptr(), |process_info| {
                    let process_id = (*process_info).UniqueProcessId.0 as u32;
                    if process_id == pid && (*process_info).NumberOfThreads > 0 {
                        // Get pointer to first thread information
                        let thread_ptr = (process_info as usize + core::mem::size_of::<SYSTEM_PROCESS_INFORMATION>())
                            as *const SYSTEM_THREAD_INFORMATION;
                        let tid = (*thread_ptr).ClientId.UniqueThread.0 as u32;
                        thread_id = Some(tid);
                    }
                });
            }

            return thread_id;

        } else if status == STATUS_INFO_LENGTH_MISMATCH.0 as i32 {
            // Buffer too small, double the size and retry
            buffer_size *= 2;
            continue;
        } else {
            // Other error
            return None;
        }
    }
}

/// Check the current state of all process threads
///
/// This function examines all threads of the specified process to determine
/// if they are all in a suspended state (STATE_WAIT with WAIT_REASON_SUSPENDED).
///
/// # Arguments
/// * `pid` - Process ID to check
///
/// # Returns
/// * `true` - All threads are suspended
/// * `false` - Process not found, has no threads, or not all threads are suspended
pub fn check_target_state(pid: u32) -> bool {
    let mut buffer_size = 0x10000usize;

    loop {
        // Allocate buffer for system process information
        let mut buffer = vec![0u8; buffer_size];

        let status = unsafe {
            nt_query_system_process_information(buffer.as_mut_ptr() as *mut _, buffer_size as u32)
        };

        if status >= 0 { // NT_SUCCESS
            let mut is_suspended = false;

            unsafe {
                walk_process_list(buffer.as_mut_ptr(), |process_info| {
                    let process_id = (*process_info).UniqueProcessId.0 as u32;
                    if process_id == pid && (*process_info).NumberOfThreads > 0 {
                        let mut all_threads_suspended = true;
                        let mut thread_ptr = (process_info as usize + core::mem::size_of::<SYSTEM_PROCESS_INFORMATION>())
                            as *const SYSTEM_THREAD_INFORMATION;

                        // Check each thread's state
                        for _ in 0..(*process_info).NumberOfThreads {
                            if (*thread_ptr).ThreadState != STATE_WAIT ||
                               (*thread_ptr).WaitReason != WAIT_REASON_SUSPENDED {
                                all_threads_suspended = false;
                                break;
                            }
                            thread_ptr = thread_ptr.add(1);
                        }

                        is_suspended = all_threads_suspended;
                    }
                });
            }

            return is_suspended;

        } else if status == STATUS_INFO_LENGTH_MISMATCH.0 as i32 {
            // Buffer too small, double the size and retry
            buffer_size *= 2;
            continue;
        } else {
            // Other error
            return false;
        }
    }
}

/// Halt a process using system calls
///
/// This function dynamically loads NtSuspendProcess from ntdll.dll and
/// suspends all threads of the specified process.
///
/// # Arguments
/// * `pid` - Process ID to suspend
///
/// # Returns
/// * `Ok(())` - Process successfully suspended
/// * `Err` - Failed to suspend process
pub fn halt_process(pid: u32) -> anyhow::Result<()> {
    type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

    unsafe {
        // Load ntdll.dll and get NtSuspendProcess function
        let wide: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(PCWSTR(wide.as_ptr()))?;
        let addr = GetProcAddress(ntdll, PCSTR(b"NtSuspendProcess\0".as_ptr()))
            .ok_or_else(|| anyhow::anyhow!("NtSuspendProcess symbol not found"))?;

        let nt_suspend_process: NtSuspendProcessFn = core::mem::transmute(addr);

        // Open process handle and suspend
        let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)?;
        let status = nt_suspend_process(process_handle);
        let _ = CloseHandle(process_handle);

        if status.0 < 0 {
            anyhow::bail!("NtSuspendProcess failed: NTSTATUS=0x{:X}", status.0);
        }
    }

    Ok(())
}

/// Resume a process using system calls
///
/// This function dynamically loads NtResumeProcess from ntdll.dll and
/// resumes all threads of the specified process.
///
/// # Arguments
/// * `pid` - Process ID to resume
///
/// # Returns
/// * `Ok(())` - Process successfully resumed
/// * `Err` - Failed to resume process
pub fn resume_process(pid: u32) -> anyhow::Result<()> {
    type NtResumeProcessFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

    unsafe {
        // Load ntdll.dll and get NtResumeProcess function
        let wide: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(PCWSTR(wide.as_ptr()))?;
        let addr = GetProcAddress(ntdll, PCSTR(b"NtResumeProcess\0".as_ptr()))
            .ok_or_else(|| anyhow::anyhow!("NtResumeProcess symbol not found"))?;

        let nt_resume_process: NtResumeProcessFn = core::mem::transmute(addr);

        // Open process handle and resume
        let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)?;
        let status = nt_resume_process(process_handle);
        let _ = CloseHandle(process_handle);

        if status.0 < 0 {
            anyhow::bail!("NtResumeProcess failed: NTSTATUS=0x{:X}", status.0);
        }
    }

    Ok(())
}

/// Convert a Windows HANDLE to its decimal string representation
///
/// This is used when passing handles as command line arguments
/// to child processes like WerFaultSecure.exe.
///
/// # Arguments
/// * `handle` - Windows HANDLE to convert
///
/// # Returns
/// * String representation of the handle's numeric value
pub fn convert_handle(handle: HANDLE) -> String {
    format!("{}", handle.0 as u64)
}

/// Query system process information using NtQuerySystemInformation
///
/// This function dynamically loads NtQuerySystemInformation from ntdll.dll
/// and queries system process information (class 5 = SystemProcessInformation).
///
/// # Safety
/// This function is unsafe because it:
/// - Dereferences raw pointers
/// - Calls system functions with raw buffers
/// - Transmutes function pointers
///
/// # Arguments
/// * `buffer` - Raw buffer to receive process information
/// * `size` - Size of the buffer in bytes
///
/// # Returns
/// * NTSTATUS code (>= 0 for success, < 0 for failure)
unsafe fn nt_query_system_process_information(buffer: *mut core::ffi::c_void, size: u32) -> i32 {
    type NtQuerySystemInformationFn = unsafe extern "system" fn(u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;

    // SystemProcessInformation = 5
    const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

    // Load ntdll.dll and get NtQuerySystemInformation function
    let wide: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let ntdll = unsafe { GetModuleHandleW(PCWSTR(wide.as_ptr())).ok().unwrap_or_default() };
    let addr = unsafe { GetProcAddress(ntdll, PCSTR(b"NtQuerySystemInformation\0".as_ptr())) };

    if let Some(function_ptr) = addr {
        let nt_query_system_info: NtQuerySystemInformationFn = unsafe { core::mem::transmute(function_ptr) };
        unsafe { nt_query_system_info(SYSTEM_PROCESS_INFORMATION_CLASS, buffer, size, core::ptr::null_mut()) }
    } else {
        -1 // Function not found
    }
}

