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
        _ => return Err(super::Error::from_raw_hresult(status).into()),
    }

    // We create the guard before calling security initialization, so that the
    // destructor is invoked and even in case the following call fails.
    let com = InitGuard(());

    // SAFETY: Simple FFI call as described in the documentation [1] using
    // default parameters. We verify the return code below.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity
    let status = unsafe {
        windows_sys::Win32::System::Com::CoInitializeSecurity(
            std::ptr::null_mut(),
            -1,
            std::ptr::null(),
            std::ptr::null(),
            windows_sys::Win32::System::Com::RPC_C_AUTHN_LEVEL_DEFAULT,
            windows_sys::Win32::System::Com::RPC_C_IMP_LEVEL_IMPERSONATE,
            std::ptr::null(),
            windows_sys::Win32::System::Com::EOAC_NONE as u32,
            std::ptr::null(),
        )
    };

    // `RPC_E_TOO_LATE` is also fine, it just means that the security was
    // initialized before.
    match status {
        windows_sys::Win32::Foundation::S_OK => (),
        windows_sys::Win32::Foundation::RPC_E_TOO_LATE => (),
        _ => return Err(super::Error::from_raw_hresult(status).into()),
    }

    Ok(com)
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

/// RAII wrapper for [WBEM service locator][1].
///
/// When this structure is dropped, the underlying COM object is automatically
/// released.
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemlocator
pub struct WbemLocator<'com> {
    ptr: *mut super::ffi::IWbemLocator,
    com: std::marker::PhantomData<&'com InitGuard>,
}

impl<'com> WbemLocator<'com> {

    /// Creates a new instance of the WBEM service locator.
    pub fn new(_: &'com InitGuard) -> std::io::Result<WbemLocator<'com>> {
        let mut result = {
            std::mem::MaybeUninit::<*mut super::ffi::IWbemLocator>::uninit()
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
            return Err(super::Error::from_raw_hresult(status).into());
        }

        Ok(WbemLocator {
            // SAFETY: We verified that the call succeeded, so `result` is now
            // properly initialized and points to a valid WBEM locator instance.
            ptr: unsafe { result.assume_init() },
            com: std::marker::PhantomData,
        })
    }

    /// Returns reference to the underlying COM object.
    pub fn as_raw_mut(&mut self) -> &mut super::ffi::IWbemLocator {
        // SAFETY: The pointer is guaranteed to be valid.
        unsafe {
            &mut *self.ptr
        }
    }

    /// Returns reference to the vtable of the underlying COM object.
    pub fn vtable(&self) -> &super::ffi::IWbemLocatorVtbl {
        // SAFETY: The pointers are guaranteed to be valid.
        unsafe {
            &*(*self.ptr).lpVtbl
        }
    }
}

impl<'com> Drop for WbemLocator<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM locator. It
        // returns a new reference count, so we are not interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            (self.vtable().Release)(self.ptr)
        };
    }
}

/// RAII wrapper for [WMI service accessor][1].
///
/// When this structure is dropped, the underlying COM object is automatically
/// released.
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
pub struct WbemServices<'com> {
    ptr: *mut super::ffi::IWbemServices,
    com: std::marker::PhantomData<&'com InitGuard>,
}

impl<'com> WbemServices<'com> {

    /// Creates a new wrapper instance from the given raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to a `IWbemServices` instance valid for
    /// the given COM initialization guard lifetime.
    pub unsafe fn from_raw_ptr(
        _: &'com InitGuard,
        ptr: *mut super::ffi::IWbemServices,
    ) -> WbemServices<'com> {
        WbemServices {
            ptr,
            com: std::marker::PhantomData,
        }
    }

    /// Returns reference to the underlying COM object.
    pub fn as_raw_mut(&mut self) -> &mut super::ffi::IWbemServices {
        // SAFETY: The pointer is guaranteed to be valid.
        unsafe {
            &mut *self.ptr
        }
    }

    /// Returns reference to the vtable of the underlying COM object.
    pub fn vtable(&self) -> &super::ffi::IWbemServicesVtbl {
        // SAFETY: The pointers are guaranteed to be valid.
        unsafe {
            &*(*self.ptr).lpVtbl
        }
    }
}

impl<'com> Drop for WbemServices<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM services
        // accessor object. It returns a new reference count, so we are not
        // interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            (self.vtable().Release)(self.ptr)
        };
    }
}

/// RAII wrapper for [WBEM class object enumerator][1].
///
/// When this structure is dropped, the underlying COM object is automatically
/// released.
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-ienumwbemclassobject
pub struct EnumWbemClassObject<'com> {
    ptr: *mut super::ffi::IEnumWbemClassObject,
    com: std::marker::PhantomData<&'com InitGuard>,
}

impl<'com> EnumWbemClassObject<'com> {

    /// Creates a new wrapper instance from the given raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to a `IEnumWbemClassObject` instance valid
    /// for the given COM initialization guard lifetime.
    pub unsafe fn from_raw_ptr(
        _: &'com InitGuard,
        ptr: *mut super::ffi::IEnumWbemClassObject,
    ) -> EnumWbemClassObject<'com> {
        EnumWbemClassObject {
            ptr,
            com: std::marker::PhantomData,
        }
    }

    /// Returns reference to the underlying COM object.
    pub fn as_raw_mut(&mut self) -> &mut super::ffi::IEnumWbemClassObject {
        // SAFETY: The pointer is guaranteed to be valid.
        unsafe {
            &mut *self.ptr
        }
    }

    /// Returns reference to the vtable of the underlying COM object.
    pub fn vtable(&self) -> &super::ffi::IEnumWbemClassObjectVtbl {
        // SAFETY: The pointers are guaranteed to be valid.
        unsafe {
            &*(*self.ptr).lpVtbl
        }
    }
}

impl<'com> Drop for EnumWbemClassObject<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM enumerator.
        // It returns a new reference count, so we are not interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            (self.vtable().Release)(self.ptr)
        };
    }
}

impl<'com> Iterator for EnumWbemClassObject<'com> {

    type Item = std::io::Result<WbemClassObject<'com>>;

    fn next(&mut self) -> Option<std::io::Result<WbemClassObject<'com>>> {
        let mut result = std::mem::MaybeUninit::uninit();
        let mut count = std::mem::MaybeUninit::uninit();

        // SAFETY: Simple FFI call as described in the documentation [1]. This
        // is based on the official example [2].
        //
        // We request only a single result, so the buffer (single `MaybeUninit`
        // cell) is sufficiently big.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
        // [2]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
        let status = unsafe {
            (self.vtable().Next)(
                self.as_raw_mut(),
                windows_sys::Win32::System::Wmi::WBEM_INFINITE,
                1,
                result.as_mut_ptr(),
                count.as_mut_ptr(),
            )
        };

        match status {
            windows_sys::Win32::System::Wmi::WBEM_S_NO_ERROR => {
                // SAFETY: This branch is reached only if the call succeeded and
                // the returned count is equal to the requested count. We can
                // thus assume that `count` is initialized and just as a sanity
                // check we verify that it matches 1 (since we only requested
                // a single result).
                let count = unsafe {
                    count.assume_init()
                };
                assert!(count == 1);

                Some(Ok(WbemClassObject {
                    // SAFETY: The call succeeded and so the sole (expected)
                    // result is now properly initialized. Thus, we can safely
                    // construct an RAII wrapper out of it.
                    ptr: unsafe { result.assume_init() },
                    com: std::marker::PhantomData,
                }))
            }
            windows_sys::Win32::System::Wmi::WBEM_S_FALSE => None,
            _ => Some(Err(super::Error::from_raw_hresult(status).into())),
        }
    }
}

/// RAII wrapper for [WBEM class objects][1].
///
/// When this structure is dropped, the underlying COM object is automatically
/// released.
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
pub struct WbemClassObject<'com> {
    ptr: *mut super::ffi::IWbemClassObject,
    com: std::marker::PhantomData<&'com InitGuard>,
}

impl<'com> WbemClassObject<'com> {

    /// Returns reference to the underlying COM object.
    pub fn as_raw_mut(&mut self) -> &mut super::ffi::IWbemClassObject {
        // SAFETY: The pointer is guaranteed to be valid.
        unsafe {
            &mut *self.ptr
        }
    }

    /// Returns reference to the vtable of the underlying COM object.
    pub fn vtable(&self) -> &super::ffi::IWbemClassObjectVtbl {
        // SAFETY: The pointers are guaranteed to be valid.
        unsafe {
            &*(*self.ptr).lpVtbl
        }
    }
}

impl<'com> Drop for WbemClassObject<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM class object.
        // It returns a new reference count, so we are not interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            (self.vtable().Release)(self.ptr)
        };
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
