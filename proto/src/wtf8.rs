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

pub fn encode_ill_formed_utf16(units: &[u8]) -> Vec<u16> {
    let mut res = Vec::new();

    let mut iter = units.iter().map(|unit| *unit).peekable();
    loop {
        let byte1 = match iter.next() {
            Some(byte1) => byte1,
            None => return res,
        };

        // TODO: Add support for proper error handling.

        // WTF-8 to a code point decoding procedure based on [1].
        //
        // [1]: https://simonsapin.github.io/wtf-8/#decoding-wtf-8
        let mut point = 0;
        match byte1 {
            0x00..=0x7F => {
                point += byte1 as u32;
            }
            0xC2..=0xDF => {
                let byte2 = iter.next().unwrap_or_else(|| todo!());
                point += ((byte1 & 0x1F) as u32) << 6;
                point += ((byte2 & 0x3F) as u32) << 0;
            }
            0xE0..=0xEF => {
                let byte2 = iter.next().unwrap_or_else(|| todo!());
                let byte3 = iter.next().unwrap_or_else(|| todo!());
                point += ((byte1 & 0x0F) as u32) << 12;
                point += ((byte2 & 0x3F) as u32) << 6;
                point += ((byte3 & 0x3F) as u32) << 0;
            }
            0xF0..=0xF4 => {
                let byte2 = iter.next().unwrap_or_else(|| todo!());
                let byte3 = iter.next().unwrap_or_else(|| todo!());
                let byte4 = iter.next().unwrap_or_else(|| todo!());
                point += ((byte1 & 0x07) as u32) << 18;
                point += ((byte2 & 0x3F) as u32) << 12;
                point += ((byte3 & 0x3F) as u32) << 6;
                point += ((byte4 & 0x3F) as u32) << 0;
            }
            _ => todo!(),
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

#[inline]
fn is_lead_surrogate(unit: &u16) -> bool {
    matches!(unit, 0xD800..=0xDBFF)
}

#[inline]
fn is_trail_surrogate(unit: &u16) -> bool {
    matches!(unit, 0xDC00..=0xDFFF)
}

#[inline]
fn is_supplementary(point: &u32) -> bool {
    matches!(point, 0x10000..=0x10FFFF)
}
