// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// RAII guarantee that COM subsystem is initialized.
///
/// When this structure is dropped, COM subsystem is de-initialized for the
/// current thread.
pub struct InitGuard(());

/// Initializes the COM subsystem.
pub fn init() -> std::io::Result<InitGuard> {
    // SAFETY: Simple FFI call as described in the documentation [1]. We
    // verify the return code below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
    let status = unsafe {
        windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_MULTITHREADED as u32,
        )
    };

    // As described in the documentation, we return the guard even if the
    // call returned `S_FALSE` or `RPC_E_CHANGED_MODE` (it means that the
    // library was initialized before) as _every_ initialization call should
    // be balanced be corresponding uninitialization.
    match status {
        windows_sys::Win32::Foundation::S_OK => {}
        windows_sys::Win32::Foundation::S_FALSE => {}
        windows_sys::Win32::Foundation::RPC_E_CHANGED_MODE => (),
        _ => return Err(std::io::Error::from_raw_os_error(status)),
    }

    Ok(InitGuard(()))
}

impl Drop for InitGuard {

    fn drop(&mut self) {
        // SAFETY: Simple FFI call as described in the documentation [1]. If we
        // reach this line, it means that the initialization did not error and
        // should be balanced by uninitialization.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/desktop/api/combaseapi/nf-combaseapi-couninitialize
        unsafe {
            windows_sys::Win32::System::Com::CoUninitialize();
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn init_ok() {
        assert!(init().is_ok());
    }

    #[test]
    fn init_sequence_ok() {
        let guard = init().unwrap();
        drop(guard);

        let guard = init().unwrap();
        drop(guard);

        let guard = init().unwrap();
        drop(guard);
    }

    #[test]
    fn init_nested_ok() {
        let guard_1 = init().unwrap();
        let guard_2 = init().unwrap();
        let guard_3 = init().unwrap();

        drop(guard_1);
        drop(guard_2);
        drop(guard_3);
    }
}
