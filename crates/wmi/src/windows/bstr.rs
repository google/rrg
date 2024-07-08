// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Owned wrapper around [`windows_sys::core::BSTR`].
pub struct BString(windows_sys::core::BSTR);

impl BString {

    /// Creates a new `BSTR` wrapper for the given string.
    ///
    /// # Panics
    ///
    /// If the given string length exceeds [`u32::MAX`] characters.
    pub fn new<S: AsRef<std::ffi::OsStr>>(string: S) -> BString {
        use std::os::windows::ffi::OsStrExt as _;

        let string_wide = string.as_ref().encode_wide().collect::<Vec<u16>>();
        let string_wide_len = match u32::try_from(string_wide.len()) {
            Ok(string_wide_len) => string_wide_len,
            Err(_) => panic!("string too long"),
        };

        // SAFETY: Simple FFI call as described in the documentation [1].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysallocstringlen
        let ptr = unsafe {
            windows_sys::Win32::Foundation::SysAllocStringLen(
                string_wide.as_ptr(),
                string_wide_len,
            )
        };

        // The call can return null only in case of insufficient memory [1].
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysallocstring#return-value
        if ptr == std::ptr::null() {
            panic!("out of memory")
        }

        BString(ptr)
    }

    /// Creates a new `BSTR` wrapper from raw pointer and takes ownership.
    ///
    /// # Safety
    ///
    /// The pointer must be valid instance of `BSTR`. It has similar semantics
    /// and requirements as [`Box::from_raw`].
    pub unsafe fn from_raw_bstr(raw: windows_sys::core::BSTR) -> BString {
        BString(raw)
    }
    /// Returns the length of the string in bytes.
    pub fn count_bytes(self) -> usize {
        self.as_bstr().count_bytes()
    }

    /// Copies the string into an owned [`std::ffi::OsString`].
    pub fn to_os_string(self) -> std::ffi::OsString {
        self.as_bstr().to_os_string()
    }

    /// Converts the string to its borrowed variant.
    pub fn as_bstr<'a>(&'a self) -> BStr<'a> {
        // SAFETY: We hold a valid `BSTR` instance with guaranteed lifetime.
        unsafe {
            BStr::from_raw_bstr(self.0)
        }
    }

    /// Returns the raw `BSTR` backing the string.
    pub fn as_raw_bstr(&self) -> windows_sys::core::BSTR {
        self.0
    }
}

impl Drop for BString {

    fn drop(&mut self) {
        // SAFETY: Simple FFI call as described in the documentation [1]. Type
        // system guarantees that the pointer has not been freed yet.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysfreestring
        unsafe {
            windows_sys::Win32::Foundation::SysFreeString(self.0)
        }
    }
}

/// Borrowed wrapper around [`windows_sys::core::BSTR`].
#[derive(Copy, Clone)]
pub struct BStr<'a> {
    raw: windows_sys::core::BSTR,
    phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a> BStr<'a> {

    /// Creates a new `BSTR` wrapper from raw pointer without taking ownership.
    ///
    /// # Safety
    ///
    /// The pointer must be valid instance of `BSTR`. It has similar semantics
    /// and requirements as [`std::slice::from_raw_parts`].
    pub unsafe fn from_raw_bstr(raw: windows_sys::core::BSTR) -> BStr<'a> {
        BStr {
            raw: raw,
            phantom: std::marker::PhantomData,
        }
    }

    /// Returns the length of the string in bytes.
    pub fn count_bytes(self) -> usize {
        // SAFETY: Every `BSTR` instance is prefixed with 4-byte length of the
        // string (excluding the null terminator) [1]. This value is placed
        // directly *before* the pointer that we have, so we offset it and read
        // from there.
        //
        // [1] https://learn.microsoft.com/en-us/previous-versions/windows/desktop/automat/bstr#remarks
        unsafe {
            *self.raw.cast::<u8>().offset(-4).cast::<u32>() as usize
        }
    }

    /// Copies the string into an owned [`std::ffi::OsString`].
    pub fn to_os_string(self) -> std::ffi::OsString {
        use std::os::windows::ffi::OsStringExt as _;

        let len = self.count_bytes() / std::mem::size_of::<u16>();

        // SAFETY: We know that the pointer is valid and calculate its length by
        // taking it byte length and dividing by the size of each character (so,
        // 2 bytes).
        std::os::windows::ffi::OsStringExt::from_wide(unsafe {
            std::slice::from_raw_parts(self.raw, len)
        })
    }

    /// Returns the raw `BSTR` backing the string.
    pub fn as_raw_bstr(self) -> windows_sys::core::BSTR {
        self.raw
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn bstring_from_str_empty() {
        let _ = BString::new("");
    }

    #[test]
    fn bstring_from_str_ascii() {
        let _ = BString::new("foobar");
    }

    #[test]
    fn bstring_from_str_unicode() {
        let _ = BString::new("załóć gęślą jaźń");
    }

    #[test]
    fn bstring_len_empty() {
        assert_eq!(BString::new("").count_bytes(), 0);
    }

    #[test]
    fn bstring_len_ascii() {
        assert_eq!(BString::new("foobar").count_bytes(), 12);
    }

    #[test]
    fn bstring_to_os_string_empty() {
        assert_eq!(BString::new("").to_os_string(), "");
    }

    #[test]
    fn bstring_to_os_string_ascii() {
        assert_eq!(BString::new("foobar").to_os_string(), "foobar");
    }

    #[test]
    fn bstring_to_os_string_unicode() {
        assert_eq!(BString::new("żółć").to_os_string(), "żółć");
    }
}
