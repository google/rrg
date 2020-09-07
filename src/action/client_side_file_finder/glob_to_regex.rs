use regex::Regex;
use crate::session::RegexParseError;

// Converts glob expression into a Rust Regex.
// E.g. "asd*[!123]??" will be converted into "asd.*[^123]..".
// This implementation is a Rust port of the cpython code:
// https://github.com/python/cpython/blob/2.7/Lib/fnmatch.py
fn glob_to_regex(pat: &str) -> Result<Regex, RegexParseError> {
    let chars : Vec<char> = pat.chars().collect();
    let mut i : usize = 0;
    let n : usize = chars.len();
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
                let mut stuff = pat[i..j].replace(r"\", r"\\");
                let stuff_chars : Vec<char> = stuff.chars().collect();
                i = j + 1;
                if stuff_chars[0] == '!' {
                    stuff = String::from("^") + &stuff[1..];
                } else if stuff_chars[0] == '^' {
                    stuff = String::from(r"\") + &stuff;
                }
                res = format!("{}[{}]", res, stuff);
            }
        } else {
            res = res + &regex::escape(&c.to_string());
        }
    }

    match Regex::new(&res) {
        Ok(v) => Ok(v),
        Err(e) => Err(RegexParseError::new(res.bytes().collect(), e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_to_regex_test() {
        assert_eq!(glob_to_regex("*").unwrap().as_str(), ".*");
        assert_eq!(glob_to_regex("?").unwrap().as_str(), ".");
        assert_eq!(glob_to_regex("a?b*").unwrap().as_str(), "a.b.*");
        assert_eq!(glob_to_regex("[abc]").unwrap().as_str(), "[abc]");
        assert_eq!(glob_to_regex("[]]").unwrap().as_str(), "[]]");
        assert_eq!(glob_to_regex("[!x]").unwrap().as_str(), "[^x]");
        assert_eq!(glob_to_regex("[^x]").unwrap().as_str(), r"[\^x]");
        assert_eq!(glob_to_regex("[x").unwrap().as_str(), r"\[x");
        assert_eq!(glob_to_regex("ąźć").unwrap().as_str(), "ąźć");
    }
}
