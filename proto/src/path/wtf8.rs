//! Utilities for working with the WTF-8 encoding.
//!
//! WTF-8 is a hack that allows to represent potentially ill-formed UTF-16 byte
//! strings in a way somewhat compatible with UTF-8. Such bugs UTF-16 strings
//! can be found for example in Windows paths for legacy reasons.
//!
//! See the official [WTF-8][wtf8] specification for more information.
//!
//! [wtf8]: https://simonsapin.github.io/wtf-8

/// Converts the given potentially ill-formed UTF-16 into a WTF-8 byte sequence.
///
/// If the given byte sequence is a well-formed UTF-16 string, then the result
/// is guaranteed to be a valid UTF-8string.
pub fn from_ill_formed_utf16<I>(units: I) -> Vec<u8>
where
    I: Iterator<Item = u16>,
{
    let mut res = Vec::new();

    let mut iter = units.peekable();
    loop {
        let unit = match iter.next() {
            Some(unit) => unit,
            None => return res,
        };

        // Potentially ill-formed UTF-16 to code point conversion based on [1].
        //
        // [1]: https://simonsapin.github.io/wtf-8/#decoding-ill-formed-utf-16
        let mut point = unit as u32;
        if is_lead_surrogate(&unit) {
            if let Some(next) = iter.next_if(is_trail_surrogate) {
                let lead = (unit as u32 - 0xD800) << 10;
                let trail = next as u32 - 0xDC00;
                point = 0x10000 + lead + trail;
            }
        }

        // Code point to WTF-8 encoding procedure based on [1].
        //
        // [1]: https://simonsapin.github.io/wtf-8/#encoding-wtf-8
        match point {
            0x0000..=0x007F => {
                res.push(point as u8);
            }
            0x0080..=0x07FF => {
                res.push(0xC0 | (point >> 6) as u8);
                res.push(0x80 | (point & 0x3F) as u8);
            }
            0x0800..=0xFFFF => {
                res.push(0xE0 | (point >> 12) as u8);
                res.push(0x80 | ((point >> 6) as u8 & 0x3F));
                res.push(0x80 | (point & 0x3F) as u8);
            }
            0x10000..=0x10FFFF => {
                res.push(0xF0 | (point >> 18) as u8);
                res.push(0x80 | ((point >> 12) as u8 & 0x3F));
                res.push(0x80 | ((point >> 6) as u8 & 0x3F));
                res.push(0x80 | (point & 0x3F) as u8);
            }
            _ => unreachable!(), // Not possible by construction.
        }
    }
}

/// Converts the given WTF-8 byte sequence into potentially ill-formed UTF-16.
///
/// If the given byte sequence is a valid UTF-8 string, then the result is
/// guaranteed to be a well-formed UTF-16 string.
///
/// If the input is not a valid WTF-8 byte sequence, an error is returned.
pub fn into_ill_formed_utf16<I>(units: I) -> Result<Vec<u16>, ParseError>
where
    I: Iterator<Item = u8>
{
    let mut res = Vec::new();

    let mut iter = units.peekable();
    loop {
        let byte1 = match iter.next() {
            Some(byte1) => byte1,
            None => return Ok(res),
        };

        // WTF-8 to a code point decoding procedure based on [1].
        //
        // [1]: https://simonsapin.github.io/wtf-8/#decoding-wtf-8
        let mut point = 0;
        match byte1 {
            0x00..=0x7F => {
                point += byte1 as u32;
            }
            0xC2..=0xDF => {
                let byte2 = iter.next().ok_or(ParseError::UnexpectedEnd)?;
                point += ((byte1 & 0x1F) as u32) << 6;
                point += ((byte2 & 0x3F) as u32) << 0;
            }
            0xE0..=0xEF => {
                let byte2 = iter.next().ok_or(ParseError::UnexpectedEnd)?;
                let byte3 = iter.next().ok_or(ParseError::UnexpectedEnd)?;
                point += ((byte1 & 0x0F) as u32) << 12;
                point += ((byte2 & 0x3F) as u32) << 6;
                point += ((byte3 & 0x3F) as u32) << 0;
            }
            0xF0..=0xF4 => {
                let byte2 = iter.next().ok_or(ParseError::UnexpectedEnd)?;
                let byte3 = iter.next().ok_or(ParseError::UnexpectedEnd)?;
                let byte4 = iter.next().ok_or(ParseError::UnexpectedEnd)?;
                point += ((byte1 & 0x07) as u32) << 18;
                point += ((byte2 & 0x3F) as u32) << 12;
                point += ((byte3 & 0x3F) as u32) << 6;
                point += ((byte4 & 0x3F) as u32) << 0;
            }
            _ => return Err(ParseError::IllegalByte(byte1)),
        }

        // Code point to potentially ill-formed UTF-16 coversion based on [1].
        //
        // [1]: https://simonsapin.github.io/wtf-8/#encoding-ill-formed-utf-16
        if is_supplementary(&point) {
            res.push(((point - 0x10000) >> 10) as u16 + 0xD800);
            res.push(((point - 0x10000) as u16 & 0x3FF) + 0xDC00);
        } else {
            res.push(point as u16);
        }
    }
}

/// Determines whether the given UTF-16 code unit is a lead surrogate.
#[inline]
fn is_lead_surrogate(unit: &u16) -> bool {
    matches!(unit, 0xD800..=0xDBFF)
}

/// Determines whether the given UTF-16 code unit is a trail surrogate.
#[inline]
fn is_trail_surrogate(unit: &u16) -> bool {
    matches!(unit, 0xDC00..=0xDFFF)
}

/// Determines whether the given code point is in the supplementary.
#[inline]
fn is_supplementary(point: &u32) -> bool {
    matches!(point, 0x10000..=0x10FFFF)
}

/// An error type for failures related to WTF-8 parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended but more bytes were expected.
    UnexpectedEnd,
    /// There was an illegal byte in the input.
    IllegalByte(u8),
}

impl std::fmt::Display for ParseError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "invalid wtf-8: ")?;

        use ParseError::*;
        match self {
            UnexpectedEnd => write!(fmt, "unexpected end"),
            IllegalByte(byte) => write!(fmt, "illegal byte: {:#02x}", byte),
        }
    }
}

impl std::error::Error for ParseError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use quickcheck_macros::quickcheck;

    #[test]
    fn from_empty() {
        assert_eq!(from_ill_formed_utf16(std::iter::empty()), b"");
    }

    #[test]
    fn from_small_bytes() {
        let bytes_utf16 = vec![0x04, 0x08, 0x16, 0x23, 0x42];
        let bytes_wtf8 = from_ill_formed_utf16(bytes_utf16.into_iter());
        assert_eq!(bytes_wtf8, b"\x04\x08\x16\x23\x42");
    }

    #[test]
    fn from_bmp_bytes() {
        let bytes_utf16 = vec![0xABCD, 0xBEEF, 0xFFFF];
        let bytes_wtf8 = from_ill_formed_utf16(bytes_utf16.into_iter());
        assert_eq!(bytes_wtf8, b"\xEA\xAF\x8D\xEB\xBB\xAF\xEF\xBF\xBF");
    }

    #[test]
    fn from_sup_bytes() {
        let bytes_utf16 = vec![0xD800, 0xDC00, 0xDBFF, 0xDFFF];
        let bytes_wtf8 = from_ill_formed_utf16(bytes_utf16.into_iter());
        assert_eq!(bytes_wtf8, b"\xF0\x90\x80\x80\xF4\x8F\xBF\xBF");
    }

    #[test]
    fn from_ascii_string() {
        let string = "foo bar baz";
        let string_wtf8 = from_ill_formed_utf16(string.encode_utf16());
        let string_utf8 = string.as_bytes();
        assert_eq!(string_wtf8, string_utf8);
    }

    #[test]
    fn from_unicode_string() {
        let string = "zażółć gęślą jaźń";
        let string_wtf8 = from_ill_formed_utf16(string.encode_utf16());
        let string_utf8 = string.as_bytes();
        assert_eq!(string_wtf8, string_utf8);
    }

    #[test]
    fn into_empty() {
        assert_eq!(into_ill_formed_utf16(std::iter::empty()), Ok(vec![]));
    }

    #[test]
    fn into_ascii_string() {
        let string = "foo bar baz";
        let string_wtf8 = into_ill_formed_utf16(string.bytes());
        let string_utf16 = string.encode_utf16().collect::<Vec<_>>();
        assert_eq!(string_wtf8, Ok(string_utf16));
    }

    #[test]
    fn into_unicode_string() {
        let string = "zażółć gęślą jaźń";
        let string_wtf8 = into_ill_formed_utf16(string.bytes());
        let string_utf16 = string.encode_utf16().collect::<Vec<_>>();
        assert_eq!(string_wtf8, Ok(string_utf16));
    }

    // TODO: Write `into` tests that cover failure scanarios.

    #[quickcheck]
    fn from_any_string(input: String) {
        let units = input.encode_utf16();

        let string_wtf8 = from_ill_formed_utf16(units);
        let string_utf8 = input.as_bytes();
        assert_eq!(string_wtf8, string_utf8);
    }

    #[quickcheck]
    fn into_from_any_string(input: String) {
        let units = input.bytes();

        let string_utf16 = into_ill_formed_utf16(units).unwrap();
        let string_wtf8 = from_ill_formed_utf16(string_utf16.into_iter());
        assert_eq!(String::from_utf8(string_wtf8).unwrap(), input);
    }

    #[quickcheck]
    fn from_into_any_units(input: Vec<u16>) {
        let units = input.iter().map(|unit| *unit);

        let string_wtf8 = from_ill_formed_utf16(units);
        let string_utf16 = into_ill_formed_utf16(string_wtf8.into_iter()).unwrap();
        assert_eq!(string_utf16, input);
    }
}
