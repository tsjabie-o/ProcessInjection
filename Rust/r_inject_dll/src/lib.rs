use windows::Win32::UI::WindowsAndMessaging::MB_OK;
use windows::{ Win32::Foundation::*, Win32::System::SystemServices::*, };
use windows::{ core::*, Win32::UI::WindowsAndMessaging::MessageBoxA, };

#[no_mangle]
#[allow(non_snake_case, unused_variables)]

extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: u32,
    _: *mut ())
    -> bool
{
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        _ => ()
    }

    true
}

fn attach() {
    unsafe{
        MessageBoxA(None, s!("Hello"), s!("Cool cool"), MB_OK);
    }
}
