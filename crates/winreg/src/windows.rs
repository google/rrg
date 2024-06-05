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
            open_raw_key((*self).into(), subkey_name)
        }
    }

    pub fn info(&self) -> std::io::Result<KeyInfo> {
        // SAFETY: Predefined keys are guaranteed to be valid open keys.
        unsafe {
            query_raw_key_info((*self).into())
        }
    }
}

impl TryFrom<windows_sys::Win32::System::Registry::HKEY> for PredefinedKey {

    type Error = InvalidPredefinedKeyError;

    fn try_from(
        hkey: windows_sys::Win32::System::Registry::HKEY,
    ) -> Result<PredefinedKey, InvalidPredefinedKeyError> {
        use windows_sys::Win32::System::Registry::*;

        match hkey {
            HKEY_CLASSES_ROOT => Ok(PredefinedKey::ClassesRoot),
            HKEY_CURRENT_CONFIG => Ok(PredefinedKey::CurrentConfig),
            HKEY_CURRENT_USER => Ok(PredefinedKey::CurrentUser),
            HKEY_CURRENT_USER_LOCAL_SETTINGS => Ok(PredefinedKey::CurrentUserLocalSettings),
            HKEY_LOCAL_MACHINE => Ok(PredefinedKey::LocalMachine),
            HKEY_PERFORMANCE_DATA => Ok(PredefinedKey::PerformanceData),
            HKEY_PERFORMANCE_NLSTEXT => Ok(PredefinedKey::PerformanceNlstext),
            HKEY_PERFORMANCE_TEXT => Ok(PredefinedKey::PerformanceText),
            HKEY_USERS => Ok(PredefinedKey::Users),
            _ => Err(InvalidPredefinedKeyError { hkey }),
        }
    }
}

impl From<PredefinedKey> for windows_sys::Win32::System::Registry::HKEY {

    fn from(key: PredefinedKey) -> windows_sys::Win32::System::Registry::HKEY {
        use windows_sys::Win32::System::Registry::*;

        match key {
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

/// The error type used when an attempt to convert a raw integer value into
/// [`PredefinedKey`] fails.
#[derive(Debug)]
pub struct InvalidPredefinedKeyError {
    hkey: windows_sys::Win32::System::Registry::HKEY,
}

impl std::fmt::Display for InvalidPredefinedKeyError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid predefined key value: {}", self.hkey)
    }
}

impl std::error::Error for InvalidPredefinedKeyError {
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
}
