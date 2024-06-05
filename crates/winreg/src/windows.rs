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
