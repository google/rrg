// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

include!(concat!(env!("OUT_DIR"), "/grr.rs"));

impl Into<DataBlob> for bool {

    fn into(self) -> DataBlob {
        DataBlob {
            boolean: Some(self),
            ..Default::default()
        }
    }
}

impl Into<DataBlob> for i64 {

    fn into(self) -> DataBlob {
        DataBlob {
            integer: Some(self),
            ..Default::default()
        }
    }
}

impl Into<DataBlob> for f32 {

    fn into(self) -> DataBlob {
        DataBlob {
            float: Some(self),
            ..Default::default()
        }
    }
}

impl Into<DataBlob> for Vec<u8> {

    fn into(self) -> DataBlob {
        DataBlob {
            data: Some(self),
            ..Default::default()
        }
    }
}

impl Into<DataBlob> for String {

    fn into(self) -> DataBlob {
        DataBlob {
            string: Some(self),
            ..Default::default()
        }
    }
}

pub fn key_value<K, V>(key: K, value: V) -> KeyValue
where
    K: Into<DataBlob>,
    V: Into<DataBlob>,
{
    KeyValue {
        k: Some(key.into()),
        v: Some(value.into()),
    }
}

/// An error type for failures of converting timestamps to microseconds.
#[derive(Clone, Debug)]
pub enum MicrosError {
    /// Attempted to convert pre-epoch system time.
    Epoch(std::time::SystemTimeError),
    /// Attempted to convert a value outside of 64-bit unsigned integer range.
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

/// Converts system time into epoch microseconds.
///
/// Because most GRR messages use epoch microseconds for representing timestamps
/// this function be be useful to convert from more idiomatic representations.
///
/// # Examples
///
/// ```
/// use rrg_proto::micros;
///
/// assert_eq!(micros(std::time::UNIX_EPOCH).unwrap(), 0);
/// ```
pub fn micros(time: std::time::SystemTime) -> Result<u64, MicrosError> {
    let time_micros = time.duration_since(std::time::UNIX_EPOCH)?.as_micros();
    Ok(std::convert::TryInto::try_into(time_micros)?)
}
