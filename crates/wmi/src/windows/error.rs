// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Idiomatic wrapper around raw Windows `HRESULT` errors.
///
/// [`HRESULT`]: windows_sys::core::HRESULT
#[derive(Debug)]
pub struct Error(windows_sys::core::HRESULT);

impl Error {

    /// Creates a new instance of the error from a particular [`HRESULT`].
    ///
    /// [`HRESULT`]: windows_sys::core::HRESULT
    pub fn from_raw_hresult(raw: windows_sys::core::HRESULT) -> Error {
        Error(raw)
    }

    /// Returns the corresponding [`std::io::ErrorKind`] for this error.
    fn kind(&self) -> std::io::ErrorKind {
        // https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values
        use windows_sys::Win32::Foundation::*;
        match self.0 {
            E_NOTIMPL => std::io::ErrorKind::Unsupported,
            E_NOINTERFACE => std::io::ErrorKind::Unsupported,
            E_POINTER => std::io::ErrorKind::InvalidInput,
            E_ABORT => std::io::ErrorKind::Interrupted,
            E_FAIL => std::io::ErrorKind::Other,
            E_UNEXPECTED => std::io::ErrorKind::Other,
            E_ACCESSDENIED => std::io::ErrorKind::PermissionDenied,
            E_HANDLE => std::io::ErrorKind::InvalidInput,
            E_OUTOFMEMORY => std::io::ErrorKind::OutOfMemory,
            E_INVALIDARG => std::io::ErrorKind::InvalidInput,
            _ => std::io::ErrorKind::Other,
        }
    }

    /// Returns a string representation of this error.
    fn as_str(&self) -> &'static str {
        // https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values
        use windows_sys::Win32::Foundation::*;
        match self.0 {
            E_NOTIMPL => "not implemented",
            E_NOINTERFACE => "no such interface supported",
            E_POINTER => "invalid pointer",
            E_ABORT => "operation aborted",
            E_FAIL => "unspecified failure",
            E_UNEXPECTED => "unexpected failure",
            E_ACCESSDENIED => "access denied",
            E_HANDLE => "invalid handle",
            E_OUTOFMEMORY => "out of memory",
            E_INVALIDARG => "invalid arguments",
            _ => "unknown",
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code: 0x{:X})", self.as_str(), self.0 as u32)
    }
}

impl std::error::Error for Error {
}

impl From<Error> for std::io::Error {

    fn from(error: Error) -> std::io::Error {
        std::io::Error::new(error.kind(), error)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn error_display_known() {
        let error = Error::from_raw_hresult(windows_sys::Win32::Foundation::E_POINTER);
        assert_eq!(error.to_string(), "invalid pointer (code: 0x80004003)");
    }

    #[test]
    fn error_display_unknown() {
        let error = Error::from_raw_hresult(0x8000F007u32 as i32);
        assert_eq!(error.to_string(), "unknown (code: 0x8000F007)");
    }
}
