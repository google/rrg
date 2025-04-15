// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Adjoins `left` and `right` using Windows registry key separator (`\`).
///
/// This is simlar to [`std::path::Path::join`] but for Windows registry keys.
///
/// # Examples
///
/// ```
/// assert_eq!(winreg::path::join("SOFTWARE", ""), "SOFTWARE");
/// assert_eq!(winreg::path::join("SOFTWARE", "Windows"), "SOFTWARE\\Windows");
/// ```
pub fn join<S>(left: S, right: S) -> std::ffi::OsString
where
    S: AsRef<std::ffi::OsStr>,
{
    let left = left.as_ref();
    let right = right.as_ref();

    let mut result = std::ffi::OsString::new();
    result.push(left);
    if !left.is_empty() && !right.is_empty() {
        result.push("\\");
    }
    result.push(right);
    result
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn join_both_empty() {
        let empty = std::ffi::OsString::new();
        assert_eq!(join(&empty, &empty), "");
    }

    #[test]
    fn join_left_empty() {
        let empty = std::ffi::OsString::new();
        let foo = std::ffi::OsString::from("foo");
        assert_eq!(join(&empty, &foo), "foo");
    }

    #[test]
    fn join_right_empty() {
        let empty = std::ffi::OsString::new();
        let foo = std::ffi::OsString::from("foo");
        assert_eq!(join(&foo, &empty), "foo");
    }

    #[test]
    fn join_both_not_empty() {
        let foo = std::ffi::OsString::from("foo");
        let bar = std::ffi::OsString::from("bar");
        assert_eq!(join(&foo, &bar), "foo\\bar");
    }
}
