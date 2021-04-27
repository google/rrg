pub fn decode_ill_formed_utf16(units: &[u16]) -> Vec<u8> {
    let mut res = Vec::new();

    let mut iter = units.iter().map(|unit| *unit).peekable();
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
            _ => panic!(), // Not possible by construction.
        }
    }
}

#[inline]
fn is_lead_surrogate(unit: &u16) -> bool {
    matches!(unit, 0xD800..=0xDBFF)
}

#[inline]
fn is_trail_surrogate(unit: &u16) -> bool {
    matches!(unit, 0xDC00..=0xDFFF)
}
