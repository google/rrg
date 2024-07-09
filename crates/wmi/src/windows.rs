// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

mod bstr;
mod com;
mod ffi;

pub fn query<S: AsRef<std::ffi::OsStr>>(query: S) -> std::io::Result<Query<S>> {
    let com = self::com::init()?;

    Ok(Query {
        query,
        com,
    })
}

pub struct Query<S: AsRef<std::ffi::OsStr>> {
    query: S,
    com: self::com::InitGuard,
}

impl<S: AsRef<std::ffi::OsStr>> Query<S> {

    pub fn rows(&self) -> std::io::Result<QueryRows<'_>> {
        let mut loc = self::com::WbemLocator::new(&self.com)?;

        let mut svc_ptr = std::mem::MaybeUninit::uninit();

        // SAFETY: Simple FFI call as described in the documentation [1]. This
        // is based on the official example [2].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
        // [2]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
        let status = unsafe {
            ((loc.vtable()).ConnectServer)(
                loc.as_raw_mut(),
                self::bstr::BString::new("root\\cimv2").as_raw_bstr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                svc_ptr.as_mut_ptr(),
            )
        };

        if status != windows_sys::Win32::Foundation::S_OK {
            return Err(std::io::Error::from_raw_os_error(status));
        }

        // SAFETY: We verified that the call succeeded, so `svc_ptr` is now
        // properly initialized and points to a valid WBEM services accessor
        // object. Thus, we can safely constructor a RAII wrapper out of it.
        let mut svc = unsafe {
            self::com::WbemServices::from_raw_ptr(&self.com, svc_ptr.assume_init())
        };

        let mut enum_ptr = std::mem::MaybeUninit::uninit();

        // SAFETY: Simple FFI call as described in the documentation [1]. This
        // is based on the official example [2].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
        // [2]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
        let status = unsafe {
            use windows_sys::Win32::System::Wmi::*;

            (svc.vtable().ExecQuery)(
                svc.as_raw_mut(),
                self::bstr::BString::new("WQL").as_raw_bstr(),
                self::bstr::BString::new(&self.query).as_raw_bstr(),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                std::ptr::null_mut(),
                enum_ptr.as_mut_ptr(),
            )
        };

        if status != windows_sys::Win32::Foundation::S_OK {
            return Err(std::io::Error::from_raw_os_error(status));
        }

        Ok(QueryRows {
            // SAFETY: We verified that the call succeeded, so `enum_ptr` is now
            // properly initialized and points to a valid WBEM enumerator. Thus,
            // we can safely construct a wrapper out of it.
            raw: unsafe {
                self::com::EnumWbemClassObject::from_raw_ptr(&self.com, enum_ptr.assume_init())
            },
        })
    }
}

pub struct QueryRows<'com> {
    raw: self::com::EnumWbemClassObject<'com>,
}

impl<'com> Iterator for QueryRows<'com> {

    type Item = std::io::Result<QueryRow>;

    fn next(&mut self) -> Option<std::io::Result<QueryRow>> {
        let mut object = match self.raw.next() {
            None => return None,
            Some(Ok(object)) => object,
            Some(Err(error)) => return Some(Err(error)),
        };

        // SAFETY: We start the enumeration on a valid object without any extra
        // flags as documented [1]. We verify the call status below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-beginenumeration
        let status = unsafe {
            (object.vtable().BeginEnumeration)(object.as_raw_mut(), 0)
        };

        if status != windows_sys::Win32::Foundation::S_OK {
            return Some(Err(std::io::Error::from_raw_os_error(status)));
        }

        let mut row = std::collections::HashMap::new();

        loop {
            let mut raw_name = std::mem::MaybeUninit::uninit();
            let mut raw_value = std::mem::MaybeUninit::uninit();

            // SAFETY: We advance the iterator [1] without any extra flags. Note
            // that we already called `BeginEnumeration`. The call should call
            // `VariantInit` on `raw_value` [2] so we should not do it upfront.
            //
            // [1]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-next
            let status = unsafe {
                (object.vtable().Next)(
                    object.as_raw_mut(),
                    0,
                    raw_name.as_mut_ptr(),
                    raw_value.as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            match status {
                windows_sys::Win32::Foundation::S_OK => (),
                windows_sys::Win32::System::Wmi::WBEM_S_NO_MORE_DATA => break,
                _ => {
                    // SAFETY: We need to terminate early, so we are required
                    // to call `EndEnumeration` now. We swallow the error, as
                    // we still want to return the one from the `Next` call.
                    let _ = unsafe {
                        (object.vtable().EndEnumeration)(object.as_raw_mut())
                    };

                    return Some(Err(std::io::Error::from_raw_os_error(status)))
                }
            }

            // SAFETY: Call to `Next` succeeded, the name should be properly
            // initialized now.
            let raw_name = unsafe {
                raw_name.assume_init()
            };

            // SAFETY: Call to `Next` succeeded, the value should be properly
            // initialized now.
            let mut raw_value = unsafe {
                raw_value.assume_init()
            };

            // SAFETY: `raw_name` is guaranteed to be a valid `BSTR` instance
            // and we should dispose it after we are done with it, so we put it
            // into the owned wrapper.
            let name = unsafe {
                self::bstr::BString::from_raw_bstr(raw_name)
            }.to_os_string();

            // SAFETY: `raw_value` is guaranteed to be a valid `VARIANT` now.
            //
            // We do not unwrap the conversion error yet, because we have to
            // clear the variant first. We do it afterwards.
            let value = unsafe {
                QueryValue::from_variant(&raw_value)
            };

            // SAFETY: We call the deinitialization function [1] after the value
            // is no longer needed as instructed [2].
            //
            // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-variantclear
            // [2]: https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-next#parameters
            let status = unsafe {
                windows_sys::Win32::System::Variant::VariantClear(&mut raw_value)
            };

            if status != windows_sys::Win32::Foundation::S_OK {
                // SAFETY: Similarly to handling faiure of `Next`, we need to
                // terminate early, so we are required to call `EndEnumeration`
                // now. We swallow the error, as we still want to return the one
                // from the `VariantClear` call.
                let _ = unsafe {
                    (object.vtable().EndEnumeration)(object.as_raw_mut())
                };

                return Some(Err(std::io::Error::from_raw_os_error(status)));
            }

            let value = match value {
                Ok(value) => value,
                Err(error) => return Some(Err(error)),
            };

            row.insert(name, value);
        }

        Some(Ok(row))
    }
}

pub type QueryRow = std::collections::HashMap<std::ffi::OsString, QueryValue>;

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
    String(std::ffi::OsString),
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

        // Based on [1] and following header files:
        //
        //   * `inc/wnet/comutil.h`
        //   * `inc/wnet/oleauto.h`
        //   * `inc/wnet/wtypes.h`
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
                    raw_value => Err(QueryValueBoolError { raw_value }.into()),
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
                Ok(QueryValue::String({
                    self::bstr::BStr::from_raw_bstr(variant.Anonymous.bstrVal)
                        .to_os_string()
                }))
            }
            raw_type => Err(QueryValueTypeError { raw_type }.into()),
        }
    }
}

#[derive(Debug)]
struct QueryValueTypeError {
    raw_type: windows_sys::Win32::System::Variant::VARENUM,
}

impl std::fmt::Display for QueryValueTypeError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "unsupported query value type: {}", self.raw_type)
    }
}

impl std::error::Error for QueryValueTypeError {
}

impl From<QueryValueTypeError> for std::io::Error {

    fn from(error: QueryValueTypeError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Unsupported, error)
    }
}

#[derive(Debug)]
struct QueryValueBoolError {
    raw_value: i16,
}

impl std::fmt::Display for QueryValueBoolError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "invalid bool value: {}", self.raw_value)
    }
}

impl std::error::Error for QueryValueBoolError {
}

impl From<QueryValueBoolError> for std::io::Error {

    fn from(error: QueryValueBoolError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn query_win32_operating_system() {
        let rows = query("SELECT * FROM Win32_OperatingSystem").unwrap()
            .rows().unwrap()
            .collect::<std::io::Result<Vec<_>>>().unwrap();

        assert_eq!(rows.len(), 1);
        assert!(matches! {
            rows[0].get(std::ffi::OsStr::new("Caption")).unwrap(),
            QueryValue::String(_),
        });
        assert!(matches! {
            rows[0].get(std::ffi::OsStr::new("Primary")).unwrap(),
            QueryValue::Bool(_),
        });
        assert!(matches! {
            rows[0].get(std::ffi::OsStr::new("CurrentTimeZone")).unwrap(),
            QueryValue::I16(_),
        });
    }

    #[test]
    fn query_win32_environment() {
        let rows = query("SELECT * FROM Win32_ComputerSystem").unwrap()
            .rows().unwrap()
            .collect::<std::io::Result<Vec<_>>>().unwrap();

        assert_eq!(rows.len(), 1);
        assert!(matches! {
            rows[0].get(std::ffi::OsStr::new("Model")).unwrap(),
            QueryValue::String(_),
        });
        assert!(matches! {
            rows[0].get(std::ffi::OsStr::new("Name")).unwrap(),
            QueryValue::String(_),
        });
        assert!(matches! {
            rows[0].get(std::ffi::OsStr::new("HypervisorPresent")).unwrap(),
            QueryValue::Bool(_),
        });
    }
}
