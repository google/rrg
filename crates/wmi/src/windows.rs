// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

mod bstr;
mod ffi;

struct ComInitGuard;

impl ComInitGuard {

    fn new() -> std::io::Result<ComInitGuard> {
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

        Ok(ComInitGuard)
    }
}

impl Drop for ComInitGuard {

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

struct WbemLocator<'com> {
    ptr: *mut self::ffi::IWbemLocator,
    com: std::marker::PhantomData<&'com ComInitGuard>,
}

impl<'com> WbemLocator<'com> {

    fn new(_: &'com ComInitGuard) -> std::io::Result<WbemLocator<'com>> {
        let mut result = {
            std::mem::MaybeUninit::<*mut self::ffi::IWbemLocator>::uninit()
        };

        // SAFETY: Simple FFI cal as described in the documentation [1]. This is
        // based on the official example [2].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
        // [2]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
        let status = unsafe {
            windows_sys::Win32::System::Com::CoCreateInstance(
                // `CLSID_WbemLocator` defined in `inc/wnet/wbemcli.h`.
                &windows_sys::core::GUID {
                    data1: 0x4590f811,
                    data2: 0x1d3a,
                    data3: 0x11d0,
                    data4: [0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
                },
                std::ptr::null_mut(),
                windows_sys::Win32::System::Com::CLSCTX_INPROC_SERVER,
                // `IID_IWbemLocator` defined in `inc/wnet/wbemcli.h`.
                &windows_sys::core::GUID {
                    data1: 0xdc12a687,
                    data2: 0x737f,
                    data3: 0x11cf,
                    data4: [0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
                },
                result.as_mut_ptr().cast::<*mut std::ffi::c_void>(),
            )
        };

        if status != windows_sys::Win32::Foundation::S_OK {
            return Err(std::io::Error::from_raw_os_error(status));
        }

        Ok(WbemLocator {
            // SAFETY: We verified that the call succeeded, so `result` is now
            // properly initialized and points to a valid WBEM locator instance.
            ptr: unsafe { result.assume_init() },
            com: std::marker::PhantomData,
        })
    }
}

impl<'com> Drop for WbemLocator<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM locator. It
        // returns a new reference count, so we are not interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            ((*(*self.ptr).lpVtbl).Release)(self.ptr)
        };
    }
}

struct WbemServicesCimv2<'com> {
    ptr: *mut self::ffi::IWbemServices,
    com: std::marker::PhantomData<&'com ComInitGuard>,
}

impl<'com> WbemServicesCimv2<'com> {

    fn new(_: &'com ComInitGuard, loc: &WbemLocator) -> std::io::Result<WbemServicesCimv2<'com>> {
        let mut result = std::mem::MaybeUninit::uninit();

        let namespace = self::bstr::BString::new("root\\cimv2");

        // SAFETY: Simple FFI call as described in the documentation [1]. This
        // is based on the official example [2].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
        // [2]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
        let status = unsafe {
            ((*(*(loc.ptr)).lpVtbl).ConnectServer)(
                loc.ptr,
                namespace.as_raw_bstr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                result.as_mut_ptr(),
            )
        };

        // We explicitly drop the namespace after the function call to guarantee
        // its lifetime.
        drop(namespace);

        if status != windows_sys::Win32::Foundation::S_OK {
            return Err(std::io::Error::from_raw_os_error(status));
        }

        Ok(WbemServicesCimv2 {
            // SAFETY: We verified that the call succeeded, so `result` is now
            // properly initialized and points to a valid WBEM services accessor
            // object.
            ptr: unsafe { result.assume_init() },
            com: std::marker::PhantomData,
        })
    }
}

impl<'com> Drop for WbemServicesCimv2<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM services
        // accessor object. It returns a new reference count, so we are not
        // interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            ((*(*self.ptr).lpVtbl).Release)(self.ptr)
        };
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn com_init_guard() {
        assert!(ComInitGuard::new().is_ok());
    }

    #[test]
    fn com_init_guard_sequence() {
        let guard = ComInitGuard::new().unwrap();
        drop(guard);

        let guard = ComInitGuard::new().unwrap();
        drop(guard);

        let guard = ComInitGuard::new().unwrap();
        drop(guard);
    }

    #[test]
    fn com_init_guard_nested() {
        let guard_1 = ComInitGuard::new().unwrap();
        let guard_2 = ComInitGuard::new().unwrap();
        let guard_3 = ComInitGuard::new().unwrap();

        drop(guard_1);
        drop(guard_2);
        drop(guard_3);
    }

    #[test]
    fn wbem_locator() {
        let com = ComInitGuard::new().unwrap();

        assert!(WbemLocator::new(&com).is_ok());
    }

    #[test]
    fn wbem_services_cimv2() {
        let com = ComInitGuard::new().unwrap();
        let loc = WbemLocator::new(&com).unwrap();

        assert!(WbemServicesCimv2::new(&com, &loc).is_ok());
    }
}
