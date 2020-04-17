// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

include!(concat!(env!("OUT_DIR"), "/grr.rs"));

#[derive(Clone, Debug)]
pub enum MicrosError {
    Epoch(std::time::SystemTimeError),
    Overflow(std::num::TryFromIntError),
}

impl std::fmt::Display for MicrosError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use MicrosError::*;

        match *self {
            Epoch(ref error) => {
                write!(fmt, "pre-epoch system time: {}", error)
            }
            Overflow(ref error) => {
                write!(fmt, "system time value too big: {}", error)
            }
        }
    }
}

impl std::error::Error for MicrosError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use MicrosError::*;

        match *self {
            Epoch(ref error) => Some(error),
            Overflow(ref error) => Some(error),
        }
    }
}

impl From<std::time::SystemTimeError> for MicrosError {

    fn from(error: std::time::SystemTimeError) -> MicrosError {
        MicrosError::Epoch(error)
    }
}

impl From<std::num::TryFromIntError> for MicrosError {

    fn from(error: std::num::TryFromIntError) -> MicrosError {
        MicrosError::Overflow(error)
    }
}

pub fn micros(time: std::time::SystemTime) -> Result<u64, MicrosError> {
    let time_micros = time.duration_since(std::time::UNIX_EPOCH)?.as_micros();
    Ok(std::convert::TryInto::try_into(time_micros)?)
}
