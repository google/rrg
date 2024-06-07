/// [Predefined key][1] of the Windows registry.
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredefinedKey {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    CurrentUserLocalSettings,
    LocalMachine,
    PerformanceData,
    PerformanceNlstext,
    PerformanceText,
    Users,
}

impl PredefinedKey {

    pub fn open(&self, subkey_name: &std::ffi::OsStr) -> std::io::Result<OpenKey> {
        // SAFETY: Predefined keys are guaranteed to be valid open keys.
        unsafe {
            open_raw_key(self.as_raw_key(), subkey_name)
        }
    }

    pub fn info(&self) -> std::io::Result<KeyInfo> {
        // SAFETY: Predefined keys are guaranteed to be valid open keys.
        unsafe {
            query_raw_key_info(self.as_raw_key())
        }
    }

    pub fn value_data(&self, value_name: &std::ffi::OsStr) -> std::io::Result<ValueData> {
        // SAFETY: Predefined keys are guaranteed to be valid open keys.
        unsafe {
            query_raw_key_value_data(self.as_raw_key(), value_name)
        }
    }

    pub fn as_raw_key(&self) -> windows_sys::Win32::System::Registry::HKEY {
        use windows_sys::Win32::System::Registry::*;

        match self {
            PredefinedKey::ClassesRoot => HKEY_CLASSES_ROOT,
            PredefinedKey::CurrentConfig => HKEY_CURRENT_CONFIG,
            PredefinedKey::CurrentUser => HKEY_CURRENT_USER,
            PredefinedKey::CurrentUserLocalSettings => HKEY_CURRENT_USER_LOCAL_SETTINGS,
            PredefinedKey::LocalMachine => HKEY_LOCAL_MACHINE,
            PredefinedKey::PerformanceData => HKEY_PERFORMANCE_DATA,
            PredefinedKey::PerformanceNlstext => HKEY_PERFORMANCE_NLSTEXT,
            PredefinedKey::PerformanceText => HKEY_PERFORMANCE_TEXT,
            PredefinedKey::Users => HKEY_USERS,
        }
    }
}

pub struct OpenKey(windows_sys::Win32::System::Registry::HKEY);

impl OpenKey {

    pub fn open(&self, subkey_name: &std::ffi::OsStr) -> std::io::Result<OpenKey> {
        // SAFETY: The key is guaranteed to be open and valid.
        unsafe {
            open_raw_key(self.0, subkey_name)
        }
    }

    pub fn info(&self) -> std::io::Result<KeyInfo> {
        // SAFETY: The key is guaranteed to be open and valid.
        unsafe {
            query_raw_key_info(self.0)
        }
    }

    pub fn value_data(&self, value_name: &std::ffi::OsStr) -> std::io::Result<ValueData> {
        // SAFETY: The key is guaranteed to be open and valid.
        unsafe {
            query_raw_key_value_data(self.0, value_name)
        }
    }
}

impl Drop for OpenKey {

    fn drop(&mut self) {
        // SAFETY: This is just an FFI call as described in the docs [1].
        //
        // Note that the key is guaranteed to be open by the type system so this
        // this call should not fail. There is no way to report an error from
        // a `Drop` implementation anyway (e.g. see [`std::fs::File`]).
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
        let _ = unsafe {
            windows_sys::Win32::System::Registry::RegCloseKey(self.0)
        };
    }
}

pub struct KeyInfo {
    // Registry key which this record describes.
    key: windows_sys::Win32::System::Registry::HKEY,
    // Maximum length of the subkey names (excluding trailing null byte).
    max_subkey_name_len: u32,
    // Maximum length of the value names (excluding trailing null byte).
    max_value_name_len: u32,
    // Maximum length of the value data (in bytes).
    max_value_data_len: u32,
}

impl KeyInfo {

    pub fn subkeys(&self) -> Subkeys {
        Subkeys {
            key: self.key,
            index: 0,
            // We use `+ 1` because the buffer should be able to hold the null
            // byte at the end which `max_subkey_name_len` does not account for.
            name_buf: Vec::with_capacity(self.max_subkey_name_len as usize + 1),
        }
    }

    pub fn values(&self) -> Values {
        Values {
            key: self.key,
            index: 0,
            // We use `+ 1` because the buffer should be able to hold the null
            // byte at the end which `max_subkey_name_len` does not account for.
            name_buf: Vec::with_capacity(self.max_value_name_len as usize + 1),
            data_buf: Vec::with_capacity(self.max_value_data_len as usize),
        }
    }
}

pub struct Subkeys {
    /// Registry key for which we yield subkeys.
    key: windows_sys::Win32::System::Registry::HKEY,
    /// Index of the key to retrieve next.
    index: u32,
    /// Buffer for the null-terminated name of the key.
    name_buf: Vec<u16>,
}

impl Iterator for Subkeys {

    type Item = std::io::Result<std::ffi::OsString>;

    fn next(&mut self) -> Option<std::io::Result<std::ffi::OsString>> {
        let mut name_len = self.name_buf.capacity() as u32;

        // SAFETY: This is just an FFI call as described in the docs [1].
        //
        // Note that the exposed Windows API is not strictly thread-safe: we use
        // `index` to advance iteration but a new key might have been added in-
        // between the calls causing some keys to be added, index to become
        // invalid or our buffer become too small. However, this will not end in
        // any undefined behaviour: we can end up with duplicated or skipped
        // items but in the worst case the API will return `ERROR_NO_MORE_ITEMS`
        // or `ERROR_MORE_DATA` which we verify below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexa
        let code = unsafe {
            windows_sys::Win32::System::Registry::RegEnumKeyExW(
                self.key,
                self.index,
                self.name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        match code {
            windows_sys::Win32::Foundation::ERROR_SUCCESS => {
                // Call succeeded, carry on.
            }
            windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS => {
                return None;
            }
            _ => {
                return Some(Err(std::io::Error::from_raw_os_error(code as i32)));
            }
        }

        self.index += 1;

        // SAFETY: We verified that the call above succeded, `name_len` should
        // now be set to the number of characters (16-bit numbers) in the bufer
        // excluding the null one at the end.
        unsafe {
            self.name_buf.set_len(name_len as usize);
        }

        Some(Ok(std::os::windows::ffi::OsStringExt::from_wide(&self.name_buf)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Value {
    /// Name of the value.
    name: std::ffi::OsString,
    /// Data associated with the value.
    data: ValueData,
}

/// Data associated with a [registry value][1].
///
/// [1]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueData {
    /// No value.
    None,
    /// Byte string.
    Bytes(Vec<u8>),
    /// Unicode-ish string.
    String(std::ffi::OsString),
    /// Unicode0ish string with unexpanded references to environment variables.
    ExpandString(std::ffi::OsString),
    /// Sequence of unicode-ish strings.
    MultiString(Vec<std::ffi::OsString>),
    /// Symbolic link to another registry key.
    Link(std::ffi::OsString),
    /// 32-bit number.
    U32(u32),
    /// 64-bit number.
    U64(u64),
}

impl ValueData {

    /// Creates a registry value data from its raw type and uninterpreted bytes.
    fn from_raw_data(
        data_type: windows_sys::Win32::System::Registry::REG_VALUE_TYPE,
        data_buf: &[u8],
    ) -> Result<ValueData, InvalidValueDataTypeError> {
        use std::os::windows::ffi::OsStringExt as _;

        let data = match data_type {
            windows_sys::Win32::System::Registry::REG_NONE => {
                ValueData::None
            }
            windows_sys::Win32::System::Registry::REG_BINARY => {
                ValueData::Bytes(data_buf.to_vec())
            }
            windows_sys::Win32::System::Registry::REG_SZ => {
                // SAFETY: The type is `REG_SZ` so we need to reinterpret the
                // buffer as 16-bit codepoint string. This is safe because we
                // do not have any assumptions on the actual bytes.
                let (align_prefix, mut data_buf_wide, align_suffix) = unsafe {
                    data_buf.align_to::<u16>()
                };
                assert!(align_prefix.is_empty());
                assert!(align_suffix.is_empty());

                // The string may or may not be null-terminated [1, 2]. We
                // remove that null byte if it is.
                //
                // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluea#remarks
                // [2]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types#string-values
                if let Some(0) = data_buf_wide.last() {
                    data_buf_wide = &data_buf_wide[0..data_buf_wide.len() - 1];
                }

                ValueData::String(std::ffi::OsString::from_wide(data_buf_wide))
            }
            windows_sys::Win32::System::Registry::REG_EXPAND_SZ => {
                // SAFETY: The type is `REG_EXPAND_SZ` so we need to reinterpret
                // the buffer as 16-bit codepoint string. This is safe because
                // we do not have any assumptions on the actual bytes.
                let (align_prefix, mut data_buf_wide, align_suffix) = unsafe {
                    data_buf.align_to::<u16>()
                };
                assert!(align_prefix.is_empty());
                assert!(align_suffix.is_empty());

                // The string may or may not be null-terminated [1, 2]. We
                // remove that null byte if it is.
                //
                // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluea#remarks
                // [2]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types#string-values
                if let Some(0) = data_buf_wide.last() {
                    data_buf_wide = &data_buf_wide[0..data_buf_wide.len() - 1];
                }

                ValueData::ExpandString(std::ffi::OsString::from_wide(data_buf_wide))
            }
            windows_sys::Win32::System::Registry::REG_MULTI_SZ => {
                // SAFETY: The type is `REG_MULTI_SZ` so we need to reinterpret
                // the buffer as 16-bit codepoint string. This is safe because
                // we do not have any assumptions on the actual bytes.
                let (align_prefix, data_buf_wide, align_suffix) = unsafe {
                    data_buf.align_to::<u16>()
                };
                assert!(align_prefix.is_empty());
                assert!(align_suffix.is_empty());

                let mut strings = Vec::new();

                for string in data_buf_wide.split(|byte| *byte == 0) {
                    // The string may or may not be null-terminated [1, 2]. We
                    // therefore be sure if we have a "genuine" empty string or
                    // if it was just missing null byte at the end. Skipping
                    // such string altogether does not seem to terrible given
                    // they should not apprear in practice anyway.
                    //
                    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluea#remarks
                    // [2]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types#string-values
                    if string.is_empty() {
                        continue;
                    }

                    strings.push(std::ffi::OsString::from_wide(string));
                }

                ValueData::MultiString(strings)
            }
            windows_sys::Win32::System::Registry::REG_LINK => {
                // SAFETY: The type is `REG_LINK` so we need to reinterpret the
                // buffer as 16-bit codepoint string. This is safe because we do
                // not have any assumptions on the actual bytes.
                let (align_prefix, mut data_buf_wide, align_suffix) = unsafe {
                    data_buf.align_to::<u16>()
                };
                assert!(align_prefix.is_empty());
                assert!(align_suffix.is_empty());

                // Note that unlike with `REG_MULTI_SZ`, `REG_EXPAND_SZ` and
                // `REG_SZ` case, the documentation does not say anything about
                // `REG_LINK` values not being properly null terminated (which
                // makes sense as they can be created only by the system that
                // should enforce that).
                assert!(matches!(data_buf_wide.last(), Some(0)));
                data_buf_wide = &data_buf_wide[0..data_buf_wide.len() - 1];

                ValueData::Link(std::ffi::OsString::from_wide(data_buf_wide))
            }
            windows_sys::Win32::System::Registry::REG_DWORD_LITTLE_ENDIAN => {
                assert!(data_buf.len() == 4);

                let octets = <[u8; 4]>::try_from(&data_buf[..]).unwrap();
                ValueData::U32(u32::from_le_bytes(octets))
            }
            windows_sys::Win32::System::Registry::REG_DWORD_BIG_ENDIAN => {
                assert!(data_buf.len() == 4);

                let octets = <[u8; 4]>::try_from(&data_buf[..]).unwrap();
                ValueData::U32(u32::from_be_bytes(octets))
            }
            windows_sys::Win32::System::Registry::REG_QWORD_LITTLE_ENDIAN => {
                assert!(data_buf.len() == 8);

                let octets = <[u8; 8]>::try_from(&data_buf[..]).unwrap();
                ValueData::U64(u64::from_le_bytes(octets))
            }
            _ => {
                // Ensure that both `REG_DWORD` and `REG_QWORD` branches are
                // actually covered by the `*_LITTLE_ENDIAN` variants.
                const _: () = {
                    use windows_sys::Win32::System::Registry::*;
                    assert!(REG_DWORD == REG_DWORD_LITTLE_ENDIAN);
                    assert!(REG_QWORD == REG_QWORD_LITTLE_ENDIAN);
                };

                // Ideally this shouldn't happen but in practice (e.g. in Wine)
                // we faced garbage types in the registry. Thus, rather than
                // marking this as impossible and panicking, we gracefully throw
                // an error.
                return Err(InvalidValueDataTypeError(data_type).into());
            }
        };

        Ok(data)
    }
}

#[derive(Debug)]
struct InvalidValueDataTypeError(windows_sys::Win32::System::Registry::REG_VALUE_TYPE);

impl std::fmt::Display for InvalidValueDataTypeError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "invalid registry value type: {}", self.0)
    }
}

impl std::error::Error for InvalidValueDataTypeError {
}

impl From<InvalidValueDataTypeError> for std::io::Error {

    fn from(error: InvalidValueDataTypeError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}

pub struct Values {
    /// Registry key for which we yield values.
    key: windows_sys::Win32::System::Registry::HKEY,
    /// Index of the value to retrieve next.
    index: u32,
    /// Buffer for the null-terminated name of the value.
    name_buf: Vec<u16>,
    /// Buffer for the actual data of the value.
    data_buf: Vec<u8>,
}

impl Iterator for Values {

    type Item = std::io::Result<Value>;

    fn next(&mut self) -> Option<std::io::Result<Value>> {
        let mut name_len = self.name_buf.capacity() as u32;
        let mut data_len = self.data_buf.capacity() as u32;
        let mut data_type = std::mem::MaybeUninit::uninit();

        // SAFETY: This is just an FFI call as described in the docs [1].
        //
        // Note that the exposed Windows API is not strictly thread-safe: we use
        // `index` to advance iteration but a new value might have been added
        // in-between the calls. However, this will not end in any undefined
        // behaviour: we can end up with duplicated or skipped items but in the
        // worst case the API will return appropriate error code which we verify
        // below.
        let code = unsafe {
            windows_sys::Win32::System::Registry::RegEnumValueW(
                self.key,
                self.index,
                self.name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                data_type.as_mut_ptr(),
                self.data_buf.as_mut_ptr(),
                &mut data_len,
            )
        };

        match code {
            windows_sys::Win32::Foundation::ERROR_SUCCESS => {
                // Call succeeded, carry on.
            }
            windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS => {
                return None;
            }
            _ => {
                return Some(Err(std::io::Error::from_raw_os_error(code as i32)));
            }
        }

        self.index += 1;

        // SAFETY: We verified that the call above succeded, `name_len` should
        // now be set to the number of characters (16-bit numbers) in the bufer
        // excluding the null one at the end.
        unsafe {
            self.name_buf.set_len(name_len as usize);
        }
        // SAFETY: We verified that the call above succeeded, `data_len` should
        // now be set to number of bytes of the value data.
        unsafe {
            self.data_buf.set_len(data_len as usize);
        }
        // SAFETY: We verified that the call above succeeded, `data_type` should
        // now be properly initialized.
        let data_type = unsafe {
            data_type.assume_init()
        };

        use std::os::windows::ffi::OsStringExt as _;

        match ValueData::from_raw_data(data_type, &self.data_buf) {
            Ok(data) => Some(Ok(Value {
                name: std::ffi::OsString::from_wide(&self.name_buf),
                data,
            })),
            Err(error) => Some(Err(error.into())),
        }
    }
}

/// Opens a subkey of the given raw registry key.
///
/// # Safety
///
/// `key` must be a valid open registry key.
unsafe fn open_raw_key(
    key: windows_sys::Win32::System::Registry::HKEY,
    subkey_name: &std::ffi::OsStr,
) -> std::io::Result<OpenKey> {
    // TODO(@panhania): Get rid of this encoding.
    use std::os::windows::ffi::OsStrExt as _;
    let mut subkey_name = subkey_name.encode_wide().collect::<Vec<u16>>();
    subkey_name.push(0);

    let mut subkey = std::mem::MaybeUninit::uninit();

    // SAFETY: This is just an FFI call as described in the docs [1].
    //
    // We use `KEY_READ` mode because this library is intended only for
    // querying registry data.
    let code = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExW(
            key,
            subkey_name.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            subkey.as_mut_ptr(),
        )
    };

    if code != windows_sys::Win32::Foundation::ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // SAFETY: We verified that the call above succeeded, the subkey is now
    // properly initialized.
    Ok(OpenKey(unsafe {
        subkey.assume_init()
    }))
}

/// Queries information about the given raw registry key.
///
/// # Safety
///
/// `key` must be a valid open registry key.
unsafe fn query_raw_key_info(
    key: windows_sys::Win32::System::Registry::HKEY,
) -> std::io::Result<KeyInfo> {
    let mut max_subkey_name_len = std::mem::MaybeUninit::uninit();
    let mut max_value_name_len = std::mem::MaybeUninit::uninit();
    let mut max_value_data_len = std::mem::MaybeUninit::uninit();

    // SAFETY: This is just an FFI call as described in the docs [1].
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw
    let code = unsafe {
        windows_sys::Win32::System::Registry::RegQueryInfoKeyW(
            key,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            max_subkey_name_len.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            max_value_name_len.as_mut_ptr(),
            max_value_data_len.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if code != windows_sys::Win32::Foundation::ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    Ok(KeyInfo {
        key,
        // SAFETY: We verified that the call above succeeded, the value is now
        // initialized.
        max_subkey_name_len: unsafe {
            max_subkey_name_len.assume_init()
        },
        // SAFETY: We verified that the call above succeeded, the value is now
        // initialized.
        max_value_name_len: unsafe {
            max_value_name_len.assume_init()
        },
        // SAFETY: We verified that the call above succeeded, the value is now
        // initialized.
        max_value_data_len: unsafe {
            max_value_data_len.assume_init()
        },
    })
}

/// Queries value data of the given registry key.
///
/// # Safety
///
/// `key` must be a valid open registry key.
unsafe fn query_raw_key_value_data(
    key: windows_sys::Win32::System::Registry::HKEY,
    value_name: &std::ffi::OsStr,
) -> std::io::Result<ValueData> {
    // TODO(@panhania): Get rid of this encoding.
    use std::os::windows::ffi::OsStrExt as _;
    let mut value_name = value_name.encode_wide().collect::<Vec<u16>>();
    value_name.push(0);

    let mut data_len = std::mem::MaybeUninit::uninit();

    // SAFETY: This is just an FFI call as described in the docs [1].
    //
    // This is the first call that will give us information about the buffer
    // length needed to hold the data (which is why most parameters are not
    // provided).
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
    let code = unsafe {
        windows_sys::Win32::System::Registry::RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            data_len.as_mut_ptr(),
        )
    };

    if code != windows_sys::Win32::Foundation::ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // SAFETY: We verified that the call above succeeded, so `data_len` should
    // be initialized to the number o bytes needed to store the data.
    let mut data_len = unsafe {
        data_len.assume_init()
    };

    let mut data_buf = Vec::with_capacity(data_len as usize);
    let mut data_type = std::mem::MaybeUninit::uninit();

    // SAFETY: This is just an FFI call as described in the docs [1].
    //
    // Here we already have the buffer allocated and we just pass it along with
    // its size. Note that even in the extremelly unlikely case of the value
    // data size changing between the calls, there is no unsafety here and the
    // call will just fail with `ERROR_MORE_DATA`.
    //
    // [1]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
    let code = unsafe {
        windows_sys::Win32::System::Registry::RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            data_type.as_mut_ptr(),
            data_buf.as_mut_ptr(),
            &mut data_len,
        )
    };

    if code != windows_sys::Win32::Foundation::ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // SAFETY: We verified that the call above succeeded, `data_type` should now
    // be initialized.
    let data_type = unsafe {
        data_type.assume_init()
    };

    // SAFETY: We verified that the call above succeeded, `data_buf` should now
    // be filled with data up to the value specified in the `data_len`.
    unsafe {
        data_buf.set_len(data_len as usize);
    }

    ValueData::from_raw_data(data_type, &data_buf)
        .map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn predefined_key_open() {
        PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap();
    }

    #[test]
    fn predefined_key_info() {
        PredefinedKey::LocalMachine
            .info().unwrap();
    }

    #[test]
    fn predefined_key_subkeys() {
        let subkeys = PredefinedKey::LocalMachine
            .info().unwrap()
            .subkeys().map(Result::unwrap).collect::<Vec<_>>();

        assert! {
            subkeys.iter()
                .find(|subkey| subkey.to_ascii_uppercase() == "SOFTWARE")
                .is_some()
        };

        assert! {
            subkeys.iter()
                .find(|subkey| subkey.to_ascii_uppercase() == "HARDWARE")
                .is_some()
        };
    }

    #[test]
    fn open_key_open() {
        PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .open(std::ffi::OsStr::new("Microsoft")).unwrap()
            .open(std::ffi::OsStr::new("Windows NT")).unwrap();
    }

    #[test]
    fn open_key_info() {
        PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .info().unwrap();
    }

    #[test]
    fn open_key_subkeys() {
        let subkeys = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .info().unwrap()
            .subkeys().map(Result::unwrap).collect::<Vec<_>>();

        assert! {
            subkeys.iter()
                .find(|subkey| subkey.to_ascii_uppercase() == "MICROSOFT")
                .is_some()
        };
    }

    #[test]
    fn open_key_values() {
        let values = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .open(std::ffi::OsStr::new("Microsoft")).unwrap()
            .open(std::ffi::OsStr::new("Windows NT")).unwrap()
            .open(std::ffi::OsStr::new("CurrentVersion")).unwrap()
            .info().unwrap()
            .values().map(Result::unwrap).collect::<Vec<_>>();

        let current_build = values.iter()
            .find(|value| value.name == "CurrentBuild").unwrap();
        assert!(matches!(current_build.data, ValueData::String(_)));

        let current_type = values.iter()
            .find(|value| value.name == "CurrentType").unwrap();
        assert!(matches!(current_type.data, ValueData::String(_)));

        let current_version = values.iter()
            .find(|value| value.name == "CurrentVersion").unwrap();
        assert!(matches!(current_version.data, ValueData::String(_)));
    }

    #[test]
    fn open_key_value_data_string() {
        let current_type = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .open(std::ffi::OsStr::new("Microsoft")).unwrap()
            .open(std::ffi::OsStr::new("Windows NT")).unwrap()
            .open(std::ffi::OsStr::new("CurrentVersion")).unwrap()
            .value_data(std::ffi::OsStr::new("CurrentType")).unwrap();
        assert!(matches!(current_type, ValueData::String(_)));
    }

    #[test]
    fn open_key_value_data_bytes() {
        let digital_product_id = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .open(std::ffi::OsStr::new("Microsoft")).unwrap()
            .open(std::ffi::OsStr::new("Windows NT")).unwrap()
            .open(std::ffi::OsStr::new("CurrentVersion")).unwrap()
            .value_data(std::ffi::OsStr::new("DigitalProductId")).unwrap();
        assert!(matches!(digital_product_id, ValueData::Bytes(_)));
    }

    #[test]
    fn open_key_value_data_expand_string() {
        let program_files_path = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SOFTWARE")).unwrap()
            .open(std::ffi::OsStr::new("Microsoft")).unwrap()
            .open(std::ffi::OsStr::new("Windows")).unwrap()
            .open(std::ffi::OsStr::new("CurrentVersion")).unwrap()
            .value_data(std::ffi::OsStr::new("ProgramFilesPath")).unwrap();
        assert!(matches!(program_files_path, ValueData::ExpandString(_)));
    }

    #[test]
    fn open_key_value_data_multi_string() {
        let service_group_order_list = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("SYSTEM")).unwrap()
            .open(std::ffi::OsStr::new("CurrentControlSet")).unwrap()
            .open(std::ffi::OsStr::new("Control")).unwrap()
            .open(std::ffi::OsStr::new("ServiceGroupOrder")).unwrap()
            .value_data(std::ffi::OsStr::new("List")).unwrap();

        match service_group_order_list {
            ValueData::MultiString(strings) => {
                assert!(!strings.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn open_key_value_data_u32() {
        let bios = PredefinedKey::LocalMachine
            .open(std::ffi::OsStr::new("HARDWARE")).unwrap()
            .open(std::ffi::OsStr::new("DESCRIPTION")).unwrap()
            .open(std::ffi::OsStr::new("System")).unwrap()
            .open(std::ffi::OsStr::new("BIOS")).unwrap();

        let bios_major_release = bios
            .value_data(std::ffi::OsStr::new("BiosMajorRelease")).unwrap();
        let bios_minor_release = bios
            .value_data(std::ffi::OsStr::new("BiosMinorRelease")).unwrap();

        assert!(matches!(bios_major_release, ValueData::U32(_)));
        assert!(matches!(bios_minor_release, ValueData::U32(_)));
    }
}
