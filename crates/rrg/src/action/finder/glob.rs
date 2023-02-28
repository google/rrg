// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::session::RegexParseError;
use regex::Regex;

/// Converts glob expression into a Rust Regex.
///
/// # Examples
/// ```
/// use rrg::action::finder::glob::glob_to_regex;
///
/// assert_eq!(glob_to_regex("as*[!12]??").unwrap().as_str(), "^as.*[^12]..$");
/// ```
///
/// This implementation is inspired by CPython code:
/// https://github.com/python/cpython/blob/2.7/Lib/fnmatch.py
pub fn glob_to_regex(pat: &str) -> Result<Regex, RegexParseError> {
    let chars: Vec<char> = pat.chars().collect();
    let mut i: usize = 0;
    let n: usize = chars.len();
    let mut res = String::new();
    while i < n {
        let c = chars[i];
        i = i + 1;
        if c == '*' {
            res = res + ".*";
        } else if c == '?' {
            res = res + ".";
        } else if c == '[' {
            let mut j = i;
            if j < n && chars[j] == '!' {
                j = j + 1;
            }
            if j < n && chars[j] == ']' {
                j = j + 1;
            }
            while j < n && chars[j] != ']' {
                j = j + 1;
            }
            if j >= n {
                res = res + r"\[";
            } else {
                let mut stuff = pat[i..j].replace(r"\", r"\\").to_owned();
                let stuff_first_char: char = stuff.chars().next().unwrap();
                i = j + 1;
                if stuff_first_char == '!' {
                    stuff = String::from("^") + &stuff[1..];
                } else if stuff_first_char == '^' {
                    stuff = String::from(r"\") + &stuff;
                }
                res = format!("{}[{}]", res, stuff);
            }
        } else {
            res = res + &regex::escape(&c.to_string());
        }
    }

    res = res.replace(r"\\", r"\");

    // Resulting regex is supposed to perform full matches on the text.
    res = format!("^{}$", res);

    match Regex::new(&res) {
        Ok(v) => Ok(v),
        Err(e) =>
            Err(RegexParseError{raw_data: res.bytes().collect(), error: e})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_to_regex() {
        assert_eq!(glob_to_regex("*").unwrap().as_str(), "^.*$");
        assert_eq!(glob_to_regex("?").unwrap().as_str(), "^.$");
        assert_eq!(glob_to_regex("a?b*").unwrap().as_str(), "^a.b.*$");
        assert_eq!(glob_to_regex("[abc]").unwrap().as_str(), "^[abc]$");
        assert_eq!(glob_to_regex("[]]").unwrap().as_str(), "^[]]$");
        assert_eq!(glob_to_regex("[!x]").unwrap().as_str(), "^[^x]$");
        assert_eq!(glob_to_regex("[^x]").unwrap().as_str(), r"^[\^x]$");
        assert_eq!(glob_to_regex("[x").unwrap().as_str(), r"^\[x$");
        assert_eq!(glob_to_regex("[a]]").unwrap().as_str(), r"^[a]\]$");
        assert_eq!(glob_to_regex(r"[\\]\\").unwrap().as_str(), r"^[\\]\\$");
        assert_eq!(glob_to_regex("ąźć").unwrap().as_str(), "^ąźć$");
    }
}
