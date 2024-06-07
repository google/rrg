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
    // Maximum length of the value (in bytes).
    max_value_len: u32,
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
    let mut max_value_len = std::mem::MaybeUninit::uninit();

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
            max_value_len.as_mut_ptr(),
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
        max_value_len: unsafe {
            max_value_len.assume_init()
        },
    })
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
}
