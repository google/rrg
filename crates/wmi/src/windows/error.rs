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
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/a2899649-a5a3-4b13-9ffa-d8394dcdac63
        use windows_sys::Win32::{Foundation::*, System::Wmi::*};
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
            WBEM_E_FAILED => std::io::ErrorKind::Other,
            WBEM_E_NOT_FOUND => std::io::ErrorKind::NotFound,
            WBEM_E_ACCESS_DENIED => std::io::ErrorKind::PermissionDenied,
            WBEM_E_PROVIDER_FAILURE => std::io::ErrorKind::Other,
            WBEM_E_TYPE_MISMATCH => std::io::ErrorKind::InvalidInput,
            WBEM_E_OUT_OF_MEMORY => std::io::ErrorKind::OutOfMemory,
            WBEM_E_INVALID_CONTEXT => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_PARAMETER => std::io::ErrorKind::InvalidInput,
            WBEM_E_NOT_AVAILABLE => std::io::ErrorKind::NotFound,
            WBEM_E_CRITICAL_ERROR => std::io::ErrorKind::Other,
            WBEM_E_NOT_SUPPORTED => std::io::ErrorKind::Unsupported,
            WBEM_E_PROVIDER_NOT_FOUND => std::io::ErrorKind::NotFound,
            WBEM_E_INVALID_PROVIDER_REGISTRATION => std::io::ErrorKind::Other,
            WBEM_E_PROVIDER_LOAD_FAILURE => std::io::ErrorKind::Other,
            WBEM_E_INITIALIZATION_FAILURE => std::io::ErrorKind::Other,
            WBEM_E_TRANSPORT_FAILURE => std::io::ErrorKind::Other,
            WBEM_E_INVALID_OPERATION => std::io::ErrorKind::InvalidInput,
            WBEM_E_ALREADY_EXISTS => std::io::ErrorKind::AlreadyExists,
            WBEM_E_UNEXPECTED => std::io::ErrorKind::Other,
            WBEM_E_INCOMPLETE_CLASS => std::io::ErrorKind::InvalidInput,
            WBEM_E_SHUTTING_DOWN => std::io::ErrorKind::Other,
            WBEM_E_INVALID_SUPERCLASS => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_NAMESPACE => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_OBJECT => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_CLASS => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_QUERY => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_QUERY_TYPE => std::io::ErrorKind::InvalidInput,
            WBEM_E_PROVIDER_NOT_CAPABLE => std::io::ErrorKind::Unsupported,
            WBEM_E_CLASS_HAS_CHILDREN => std::io::ErrorKind::Other,
            WBEM_E_CLASS_HAS_INSTANCES => std::io::ErrorKind::Other,
            WBEM_E_ILLEGAL_NULL => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_CIM_TYPE => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_METHOD => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_METHOD_PARAMETERS => std::io::ErrorKind::InvalidInput,
            WBEM_E_INVALID_PROPERTY => std::io::ErrorKind::InvalidInput,
            WBEM_E_CALL_CANCELLED => std::io::ErrorKind::Other,
            WBEM_E_INVALID_OBJECT_PATH => std::io::ErrorKind::InvalidInput,
            // TODO(rust-lang/rust/issues/86442): Replace with `StorageFull`
            // once it is stable.
            WBEM_E_OUT_OF_DISK_SPACE => std::io::ErrorKind::Other,
            WBEM_E_UNSUPPORTED_PUT_EXTENSION => std::io::ErrorKind::Other,
            WBEM_E_QUOTA_VIOLATION => std::io::ErrorKind::Other,
            WBEM_E_SERVER_TOO_BUSY => std::io::ErrorKind::Other,
            WBEM_E_METHOD_NOT_IMPLEMENTED => std::io::ErrorKind::Unsupported,
            WBEM_E_METHOD_DISABLED => std::io::ErrorKind::Unsupported,
            WBEM_E_UNPARSABLE_QUERY => std::io::ErrorKind::InvalidData,
            WBEM_E_NOT_EVENT_CLASS => std::io::ErrorKind::InvalidData,
            WBEM_E_MISSING_GROUP_WITHIN => std::io::ErrorKind::InvalidData,
            WBEM_E_MISSING_AGGREGATION_LIST => std::io::ErrorKind::InvalidData,
            WBEM_E_PROPERTY_NOT_AN_OBJECT => std::io::ErrorKind::InvalidData,
            WBEM_E_AGGREGATING_BY_OBJECT => std::io::ErrorKind::InvalidData,
            WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING => std::io::ErrorKind::Other,
            WBEM_E_QUEUE_OVERFLOW => std::io::ErrorKind::Other,
            WBEM_E_PRIVILEGE_NOT_HELD => std::io::ErrorKind::PermissionDenied,
            WBEM_E_INVALID_OPERATOR => std::io::ErrorKind::InvalidData,
            WBEM_E_CANNOT_BE_ABSTRACT => std::io::ErrorKind::Other,
            WBEM_E_AMENDED_OBJECT => std::io::ErrorKind::Other,
            WBEM_E_VETO_PUT => std::io::ErrorKind::Unsupported,
            WBEM_E_PROVIDER_SUSPENDED => std::io::ErrorKind::Other,
            WBEM_E_ENCRYPTED_CONNECTION_REQUIRED => std::io::ErrorKind::Other,
            WBEM_E_PROVIDER_TIMED_OUT => std::io::ErrorKind::TimedOut,
            WBEM_E_NO_KEY => std::io::ErrorKind::InvalidInput,
            WBEM_E_PROVIDER_DISABLED => std::io::ErrorKind::Other,
            _ => std::io::ErrorKind::Other,
        }
    }

    /// Returns a string representation of this error.
    fn as_str(&self) -> &'static str {
        // https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/a2899649-a5a3-4b13-9ffa-d8394dcdac63
        use windows_sys::Win32::{Foundation::*, System::Wmi::*};
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
            WBEM_E_FAILED => "unknown error while processing the request",
            WBEM_E_NOT_FOUND => "object specified in the path does not exist",
            WBEM_E_ACCESS_DENIED => "access denied",
            WBEM_E_PROVIDER_FAILURE => "provider failure",
            WBEM_E_TYPE_MISMATCH => "type mismatch",
            WBEM_E_OUT_OF_MEMORY => "out of memory",
            WBEM_E_INVALID_CONTEXT => "invalid context",
            WBEM_E_INVALID_PARAMETER => "invalid method parameter",
            WBEM_E_NOT_AVAILABLE => "resource not available",
            WBEM_E_CRITICAL_ERROR => "catastrophic failure",
            WBEM_E_NOT_SUPPORTED => "attempted operation is not supported",
            WBEM_E_PROVIDER_NOT_FOUND => "provider not found",
            WBEM_E_INVALID_PROVIDER_REGISTRATION => "invalid provider registration",
            WBEM_E_PROVIDER_LOAD_FAILURE => "provider load failure",
            WBEM_E_INITIALIZATION_FAILURE => "initialization failure",
            WBEM_E_TRANSPORT_FAILURE => "network problem detected",
            WBEM_E_INVALID_OPERATION => "operation performed not valid",
            WBEM_E_ALREADY_EXISTS => "CIM object already exists",
            WBEM_E_UNEXPECTED => "unspecified error",
            WBEM_E_INCOMPLETE_CLASS => "class not registered with WMI",
            WBEM_E_SHUTTING_DOWN => "server is shutting down",
            WBEM_E_INVALID_SUPERCLASS => "parent class not found",
            WBEM_E_INVALID_NAMESPACE => "namespace not found",
            WBEM_E_INVALID_OBJECT => "CIM object not valid",
            WBEM_E_INVALID_CLASS => "invalid class name",
            WBEM_E_INVALID_QUERY => "invalid query",
            WBEM_E_INVALID_QUERY_TYPE => "invalid query language",
            WBEM_E_PROVIDER_NOT_CAPABLE => "operation unsupported on CIM class",
            WBEM_E_CLASS_HAS_CHILDREN => "class has children",
            WBEM_E_CLASS_HAS_INSTANCES => "class has instances",
            WBEM_E_ILLEGAL_NULL => "non-null property set to null",
            WBEM_E_INVALID_CIM_TYPE => "invalid CIM type",
            WBEM_E_INVALID_METHOD => "invalid method",
            WBEM_E_INVALID_METHOD_PARAMETERS => "invalid method parameters",
            WBEM_E_INVALID_PROPERTY => "property not present in CIM database",
            WBEM_E_CALL_CANCELLED => "execution of request cancelled",
            WBEM_E_INVALID_OBJECT_PATH => "object path syntactically invalid",
            WBEM_E_OUT_OF_DISK_SPACE => "out of disk space",
            WBEM_E_UNSUPPORTED_PUT_EXTENSION => "unsupported put extension",
            WBEM_E_QUOTA_VIOLATION => "quota violation",
            WBEM_E_SERVER_TOO_BUSY => "server too busy",
            WBEM_E_METHOD_NOT_IMPLEMENTED => "method not implemented",
            WBEM_E_METHOD_DISABLED => "method disabled",
            WBEM_E_UNPARSABLE_QUERY => "unparsable query",
            WBEM_E_NOT_EVENT_CLASS => "`FROM` clause class not derived from `Event`",
            WBEM_E_MISSING_GROUP_WITHIN => "`GROUP BY` clause missing `WITHIN`",
            WBEM_E_MISSING_AGGREGATION_LIST => "`GROUP BY` used with aggregation",
            WBEM_E_PROPERTY_NOT_AN_OBJECT => "`GROUP BY` property not an object",
            WBEM_E_AGGREGATING_BY_OBJECT => "`GROUP BY` aggregating by object",
            WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING => "CIM database backup requested while used",
            WBEM_E_QUEUE_OVERFLOW => "event queue overflow",
            WBEM_E_PRIVILEGE_NOT_HELD => "privilege for CIM classes not found",
            WBEM_E_INVALID_OPERATOR => "query operator invalid for the type",
            WBEM_E_CANNOT_BE_ABSTRACT => "CIM class cannot be abstract",
            WBEM_E_AMENDED_OBJECT => "CIM class not ammendable",
            WBEM_E_VETO_PUT => "put operation unsupported by the CIM class",
            WBEM_E_PROVIDER_SUSPENDED => "provider suspended",
            WBEM_E_ENCRYPTED_CONNECTION_REQUIRED => "encrypted connection required",
            WBEM_E_PROVIDER_TIMED_OUT => "provider timed out",
            WBEM_E_NO_KEY => "put operation without value for key properties",
            WBEM_E_PROVIDER_DISABLED => "provider disabled",
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
