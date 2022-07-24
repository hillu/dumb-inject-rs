#![cfg(windows)]

extern crate winapi;

use std::ffi::{CStr,CString};
use std::path::Path;
use std::ptr::null_mut;

use winapi::shared::{minwindef::*,
                     windef::*};

use winapi::um::{errhandlingapi::*,
                 libloaderapi::*,
                 processthreadsapi::*,
                 psapi::*,
                 winbase::*,
                 winuser::*,
                 winnt::{*,INT},
                 memoryapi::*,
                 securitybaseapi::*};

fn msg_title() -> CString {
    let dll_name = unsafe { CStr::from_ptr(DLL_NAME.as_ref().unwrap().as_ptr()) }
    .to_string_lossy();
    let prog_name = unsafe { CStr::from_ptr(PROG_NAME.as_ref().unwrap().as_ptr()) }
    .to_string_lossy();

    let dll_name = Path::new(dll_name.as_ref()).to_path_buf();
    let prog_name = Path::new(prog_name.as_ref()).to_path_buf();

    CString::new(
	format!("{} ({})",
		dll_name.file_name().unwrap().to_string_lossy(),
		prog_name.file_name().unwrap().to_string_lossy())
    ).unwrap()
}

/// Show error-themed message box
fn error_msg(s: &str) {
    let msg = CString::new(s).unwrap();
    unsafe {
        MessageBoxA(
            null_mut(),
            msg.as_ptr(),
            msg_title().as_ptr(),
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
            msg_title().as_ptr(),
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

/// Somewhat ergonomic wrapper around OpenProcess
fn open_process(pid: u32) -> Result<HANDLE,Box<dyn std::error::Error>> {
    match unsafe { OpenProcess(PROCESS_ALL_ACCESS,  FALSE, pid as _) } {
	h if h == null_mut() => Err(get_last_error_string().into()),
	h => Ok(h)
    }
}

/// Produce formatted message based on GetLastError
fn get_last_error_string() -> String {
    let r = unsafe { GetLastError() };
    format_error(r)
}

/// Somewhat ergonomic wrapper around FormatMessage
fn format_error(r: DWORD) -> String {
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
    unsafe { CStr::from_ptr(msg.as_ptr()) } .to_string_lossy().to_string()
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

/// This function implements the functionality of the "inject" interface.
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
                           DLL_NAME.as_ref().unwrap().as_ptr().cast(),
                           MAX_PATH,
                           null_mut())
    };
    
    let ll_addr_fnptr = 
	(&( ll_addr as *const fn() ) as *const _) as *const _;

    let _thread_handle = unsafe {
        CreateRemoteThread(proc_handle,
                           null_mut(),
                           0,
                           Some(*ll_addr_fnptr),
                           dllname_remote_addr,
                           0,
                           null_mut())
    };

    // Cleanup
    unsafe {
        VirtualFreeEx(proc_handle, dllname_remote_addr, MAX_PATH, MEM_DECOMMIT|MEM_RELEASE)
    };
    
    Ok(())
}

/// This function implements the functionality of the "enumerate" interface.
fn do_enum(params: Vec<&str>) -> Result<(),Box<dyn std::error::Error>> {
    if params.len() != 1 {
        return Err("usage: <pid>".into());
    }
    let pid: u32 = params[0].parse().map_err(|e|format!("parse pid: {}", e))?;
    get_sedebug_priv().map_err(|e|format!("AdjustPRivileges: {}", e))?;
    let proc_handle = open_process(pid).map_err(|e|format!("OpenProcess: {}: {}", pid, e))?;

    let module_handles =
    {
        let mut buf: Vec<HMODULE> = Vec::new();
        buf.resize(8, null_mut());
        let mut needed: DWORD = 0;
        loop {
            match unsafe {
                EnumProcessModules(
                    proc_handle,
                    buf.as_mut_ptr(),
                    (buf.len() * std::mem::size_of::<HMODULE>()) as _,
                    &mut needed
                )
            } {
                TRUE => {
                    let prev_len = buf.len();
                    buf.resize(needed as usize / std::mem::size_of::<HMODULE>(), null_mut());
                    if (needed as usize) / std::mem::size_of::<HMODULE>() <= prev_len {
                        break;
                    }
                },
                _ => return Err(get_last_error_string().into()),
            }
        }
        buf
    };

    let mut msg = "Modules:\n\n".to_string();
    for handle in module_handles {
        let mut buf = [0 as CHAR; MAX_PATH];
        unsafe {
            GetModuleFileNameExA(proc_handle,
				 handle,
				 buf.as_mut_ptr(),
				 MAX_PATH as _)
        };
	msg += &format!("{:08x} {}\n",
			handle as u64,
			&unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy());
    }

    info_msg(&msg);

    Ok(())
}

/// This function implements the functionality of the "unload" interface.
///
/// It looks for modules in the target process whose filename is equal
/// to its own filename. If such a module is found, it spawns a remote
/// threrad that calls FreeLibrary on the module handle.
fn do_unload(params: Vec<&str>) -> Result<(),Box<dyn std::error::Error>> {
    if params.len() != 1 {
        return Err("usage: <pid>".into());
    }
    let pid: u32 = params[0].parse().map_err(|e|format!("parse pid: {}", e))?;
    get_sedebug_priv().map_err(|e|format!("AdjustPRivileges: {}", e))?;
    let proc_handle = open_process(pid).map_err(|e|format!("OpenProcess: {}: {}", pid, e))?;

    let module_handles =
    {
        let mut buf: Vec<HMODULE> = Vec::new();
        buf.resize(8, null_mut());
        let mut needed: DWORD = 0;
        loop {
            match unsafe {
                EnumProcessModules(
                    proc_handle,
                    buf.as_mut_ptr(),
                    (buf.len() * std::mem::size_of::<HMODULE>()) as _,
                    &mut needed
                )
            } {
                TRUE => {
                    let prev_len = buf.len();
                    buf.resize(needed as usize / std::mem::size_of::<HMODULE>(), null_mut());
                    if (needed as usize) / std::mem::size_of::<HMODULE>() <= prev_len {
                        break;
                    }
                },
                _ => return Err(get_last_error_string().into()),
            }
        }
        buf
    };

    let dll_name = unsafe { CStr::from_ptr(DLL_NAME.as_ref().unwrap().as_ptr()) };
    let mut found = false;

    for handle in module_handles {
        let mut buf = [0 as CHAR; MAX_PATH];
        unsafe {
            GetModuleFileNameExA(proc_handle, handle, buf.as_mut_ptr(), MAX_PATH as _)
        };
        let module_name = unsafe { CStr::from_ptr(buf.as_ptr()) };
        if module_name == dll_name {
            info_msg(&format!("Unloading DLL: \n{:08x} {}",
			      handle as u64, module_name.to_string_lossy()));

            let fl_addr = resolve_addr("kernel32.dll", "FreeLibrary")?;
            let fl_addr_fnptr =
		(&( fl_addr as *const fn() ) as *const _) as *const _;

            let _thread_handle = unsafe {
                CreateRemoteThread(proc_handle,
                                   null_mut(),
                                   0,
                                   Some(*fl_addr_fnptr),
                                   handle as _,
                                   0,
                                   null_mut())
            };
	    found = true;
            break;
        }
    }

    if !found {
	error_msg("DLL not found in target process");
    }

    Ok(())
}

/// This function gets called by DllMain if a process other than
/// rundll32 has loaded htis DLL.
///
/// At this point we can pretty much do anything, for example create
/// long-running threads.
///
/// Let's just tell the user that everything went well and provide
/// them with a cmd.exe.
fn on_load() {
    info_msg("DLL was injected successfully.");

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
static mut PROG_NAME: Option<Vec<CHAR>> = None;

/// This function is called by DllMain if a process other than
/// rundll32 (i.e. the target process) is unloading this DLL.
fn on_unload() {
    info_msg("DLL is being unloaded.");
}

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
pub extern fn enumerate(_hwnd: HWND, _hinst: HINSTANCE, cmdline: LPCSTR, _cmdshow: INT) {
    let cmdline = unsafe { CStr::from_ptr(cmdline) } .to_string_lossy();
    let params = cmdline.split(' ').filter(|&s| s != "").collect::<Vec<_>>();

    match do_enum(params) {
        Ok(_) => {},
        Err(s) => error_msg(&s.to_string()),
    };
}

#[no_mangle]
pub extern fn unload(_hwnd: HWND, _hinst: HINSTANCE, cmdline: LPCSTR, _cmdshow: INT) {
    let cmdline = unsafe { CStr::from_ptr(cmdline) } .to_string_lossy();
    let params = cmdline.split(' ').filter(|&s| s != "").collect::<Vec<_>>();

    match do_unload(params) {
        Ok(_) => {},
        Err(s) => error_msg(&s.to_string()),
    };
}

#[no_mangle]
pub extern fn DllMain(hdll: HINSTANCE, fdw_reason: DWORD, _reserved: LPVOID) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            let mut buf = [0_ as CHAR; MAX_PATH];
            unsafe { GetModuleFileNameA( hdll, buf.as_mut_ptr().cast(), MAX_PATH as _) };
	    unsafe { DLL_NAME = Some(Vec::from(&buf[..])); }

            unsafe { GetModuleFileNameA( null_mut(), buf.as_mut_ptr().cast(), MAX_PATH as _) };
	    unsafe { PROG_NAME = Some(Vec::from(&buf[..])); }

            let progname = unsafe { CStr::from_ptr(buf.as_ptr().cast()) } .to_str().unwrap();
            if !progname.to_lowercase().contains("rundll32") {
                on_load();
            }
        },
        DLL_PROCESS_DETACH => {
	    let progname = unsafe {
		CStr::from_ptr(PROG_NAME.as_ref().unwrap().as_ptr())
	    } .to_str().unwrap();
            if !progname.to_lowercase().contains("rundll32") {
                on_unload();
            }
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        _ => {},
    };
    TRUE
}
