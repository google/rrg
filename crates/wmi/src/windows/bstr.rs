// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub struct BString(windows_sys::core::BSTR);

impl BString {

    pub fn as_raw_bstr(&self) -> windows_sys::core::BSTR {
        self.0
    }
}

impl<S: AsRef<std::ffi::OsStr>> From<S> for BString {

    fn from(string: S) -> BString {
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn bstring_from_str_ascii() {
        let _ = BString::from("foobar");
    }

    #[test]
    fn bstring_from_str_unicode() {
        let _ = BString::from("załóć gęślą jaźń");
    }

}
