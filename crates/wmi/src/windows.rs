// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

mod bstr;
mod ffi;

#[derive(Debug, Clone, PartialEq)]
pub enum QueryValue {
    Illegal,
    None,
    Bool(bool),
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    F32(f32),
    F64(f64),
    // TODO(@panhania): Add support for other types.
}

impl QueryValue {

    /// Constructs a value from native [`VARIANT`] instance.
    ///
    /// # Safety
    ///
    /// `variant` must be a properly initialized [`VARIANT`] instance.
    unsafe fn from_variant(
        variant: &windows_sys::Win32::System::Variant::VARIANT,
    ) -> std::io::Result<QueryValue> {
        let variant = variant.Anonymous.Anonymous;

        // Based on `inc/wnet/comutil.h`, `inc/wnet/oleauto.h` and [1].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-variant
        match variant.vt {
            windows_sys::Win32::System::Variant::VT_EMPTY => {
                Ok(QueryValue::None)
            }
            windows_sys::Win32::System::Variant::VT_NULL => {
                Ok(QueryValue::None)
            }
            windows_sys::Win32::System::Variant::VT_BOOL => {
                match variant.Anonymous.boolVal {
                    0 => Ok(QueryValue::Bool(false)),
                    -1 => Ok(QueryValue::Bool(true)),
                    value => Err(std::io::ErrorKind::InvalidData.into()),
                }
            }
            windows_sys::Win32::System::Variant::VT_UI1 => {
                Ok(QueryValue::U8(variant.Anonymous.bVal))
            }
            windows_sys::Win32::System::Variant::VT_I1 => {
                // According to `inc/wnet/oleauto.h`, `VT_I1` corresponds to
                // `cVal` and should be a signed char but this is not what the
                // type says, so we reinterpret it.
                Ok(QueryValue::I8(variant.Anonymous.cVal as i8))
            }
            windows_sys::Win32::System::Variant::VT_UI2 => {
                Ok(QueryValue::U16(variant.Anonymous.uiVal))
            }
            windows_sys::Win32::System::Variant::VT_I2 => {
                Ok(QueryValue::I16(variant.Anonymous.iVal))
            }
            windows_sys::Win32::System::Variant::VT_UI4 => {
                Ok(QueryValue::U32(variant.Anonymous.ulVal))
            }
            windows_sys::Win32::System::Variant::VT_I4 => {
                Ok(QueryValue::I32(variant.Anonymous.lVal))
            }
            windows_sys::Win32::System::Variant::VT_UI8 => {
                Ok(QueryValue::U64(variant.Anonymous.ullVal))
            }
            windows_sys::Win32::System::Variant::VT_I8 => {
                Ok(QueryValue::I64(variant.Anonymous.llVal))
            }
            windows_sys::Win32::System::Variant::VT_R4 => {
                Ok(QueryValue::F32(variant.Anonymous.fltVal))
            }
            windows_sys::Win32::System::Variant::VT_R8 => {
                Ok(QueryValue::F64(variant.Anonymous.dblVal))
            }
            windows_sys::Win32::System::Variant::VT_BSTR => {
                // TODO(@panhania): Add support for this.
                Err(std::io::ErrorKind::Unsupported.into())
            }
            _ => Err(std::io::ErrorKind::Unsupported.into())
        }
    }
}

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

    fn query<S>(&self, query: S) -> std::io::Result<WbemEnumClassObject<'com>>
    where
        S: AsRef<std::ffi::OsStr>,
    {
        let mut result = std::mem::MaybeUninit::uninit();

        // SAFETY: Simple FFI call as described in the documentation [1]. This
        // is based on the official example [2].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
        // [2]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
        let status = unsafe {
            use windows_sys::Win32::System::Wmi::*;

            ((*(*self.ptr).lpVtbl).ExecQuery)(
                self.ptr,
                self::bstr::BString::new("WQL").as_raw_bstr(),
                self::bstr::BString::new(query).as_raw_bstr(),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                std::ptr::null_mut(),
                result.as_mut_ptr(),
            )
        };

        if status != windows_sys::Win32::Foundation::S_OK {
            return Err(std::io::Error::from_raw_os_error(status));
        }

        Ok(WbemEnumClassObject {
            // SAFETY: We verified that the call succeeded, so `result` is now
            // properly initialized and points to a valid WBEM enumerator.
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

struct WbemEnumClassObject<'com> {
    ptr: *mut self::ffi::IEnumWbemClassObject,
    com: std::marker::PhantomData<&'com ComInitGuard>,
}

impl<'com> WbemEnumClassObject<'com> {

    fn next(&mut self) -> std::io::Result<Option<WbemClassObject<'com>>> {
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
            ((*(*self.ptr).lpVtbl).Next)(
                self.ptr,
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
                // a single result.
                let count = unsafe {
                    count.assume_init()
                };
                assert!(count == 1);

                Ok(Some(WbemClassObject {
                    // SAFETY: The call succeeded and it initialized the sole
                    // (expected) result.
                    ptr: unsafe { result.assume_init() },
                    com: std::marker::PhantomData,
                }))
            }
            windows_sys::Win32::System::Wmi::WBEM_S_FALSE => Ok(None),
            _ => Err(std::io::Error::from_raw_os_error(status)),
        }
    }
}

impl<'com> Drop for WbemEnumClassObject<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM enumerator.
        // It returns a new reference count, so we are not interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            ((*(*self.ptr).lpVtbl).Release)(self.ptr)
        };
    }
}

struct WbemClassObject<'com> {
    ptr: *mut self::ffi::IWbemClassObject,
    com: std::marker::PhantomData<&'com ComInitGuard>,
}

impl<'com> Drop for WbemClassObject<'com> {

    fn drop(&mut self) {
        // SAFETY: We call the [`Release`][1] method of valid WBEM enumerator.
        // It returns a new reference count, so we are not interested in it.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        let _ = unsafe {
            ((*(*self.ptr).lpVtbl).Release)(self.ptr)
        };
    }
}

struct Variant(windows_sys::Win32::System::Variant::VARIANT);

impl Variant {

    pub fn new() -> Variant {
        let mut raw = std::mem::MaybeUninit::uninit();

        // SAFETY: We call the initialization function as documented [1].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantinit
        unsafe {
            windows_sys::Win32::System::Variant::VariantInit(raw.as_mut_ptr());
        }

        // SAFETY: Value is now correctly initialized.
        Variant(unsafe { raw.assume_init() })
    }
}

impl Drop for Variant {

    fn drop(&mut self) {
        // SAFETY: We call the deinitialization function as documented [1].
        //
        // The function can return an error but it is not possible to handle
        // it in `Drop` implementation.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear
        let _ = unsafe {
            windows_sys::Win32::System::Variant::VariantClear(&mut self.0);
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
    fn wbem_services_cimv2_query() {
        let com = ComInitGuard::new().unwrap();
        let loc = WbemLocator::new(&com).unwrap();

        WbemServicesCimv2::new(&com, &loc).unwrap()
            .query("SELECT * FROM Win32_OperatingSystem").unwrap();
    }
}
