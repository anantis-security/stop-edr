/// Windows privilege management utilities
///
/// This module provides functions for enabling Windows privileges
/// required for process manipulation and debugging using dinvoke_rs.

use windows::core::PCWSTR;

/// Setup required system permissions
pub fn setup_permissions() -> anyhow::Result<()> {
    use windows::{
        Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    };

    unsafe {
        // Load system library and get privilege adjustment function
        let wide: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(PCWSTR(wide.as_ptr()))?;
        let addr = GetProcAddress(ntdll, windows::core::PCSTR(b"RtlAdjustPrivilege\0".as_ptr()))
            .ok_or_else(|| anyhow::anyhow!("System function not found"))?;

        type PrivilegeAdjustFn = unsafe extern "system" fn(u32, u8, u8, *mut u8) -> i32;
        let adjust_privilege: PrivilegeAdjustFn = std::mem::transmute(addr);

        let privilege_id: u32 = 20; // System debug privilege
        let enable_flag: u8 = 1; // Enable the privilege
        let process_level: u8 = 0; // Enable for current process
        let mut enabled_status: u8 = 0;

        let result = adjust_privilege(privilege_id, enable_flag, process_level, &mut enabled_status);

        if result == 0 {
            println!("System permissions configured successfully");
            Ok(())
        } else {
            anyhow::bail!("Permission setup failed: NTSTATUS=0x{:X}", result as u32);
        }
    }
}