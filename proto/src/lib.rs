// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

include!(concat!(env!("OUT_DIR"), "/grr.rs"));

impl From<bool> for DataBlob {

    fn from(value: bool) -> DataBlob {
        DataBlob {
            boolean: Some(value),
            ..Default::default()
        }
    }
}

impl From<i64> for DataBlob {

    fn from(value: i64) -> DataBlob {
        DataBlob {
            integer: Some(value),
            ..Default::default()
        }
    }
}

impl From<f32> for DataBlob {

    fn from(value: f32) -> DataBlob {
        DataBlob {
            float: Some(value),
            ..Default::default()
        }
    }
}

impl From<Vec<u8>> for DataBlob {

    fn from(value: Vec<u8>) -> DataBlob {
        DataBlob {
            data: Some(value),
            ..Default::default()
        }
    }
}

impl From<String> for DataBlob {

    fn from(value: String) -> DataBlob  {
        DataBlob {
            string: Some(value),
            ..Default::default()
        }
    }
}

impl KeyValue {

    /// Creates an empty key-value.
    ///
    /// Both the key and the value are going to be equal to `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg_proto::KeyValue;
    ///
    /// let entry = KeyValue::empty();
    /// assert_eq!(entry.k, None);
    /// assert_eq!(entry.v, None);
    /// ```
    pub fn empty() -> KeyValue {
        KeyValue {
            k: None,
            v: None,
        }
    }

    /// Creates a key-value pair.
    ///
    /// Both the key and the value are going to be equal to the given values.
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg_proto::KeyValue;
    ///
    /// let entry = KeyValue::pair(String::from("foo"), 42i64);
    /// assert_eq!(entry.k.unwrap().string, Some(String::from("foo")));
    /// assert_eq!(entry.v.unwrap().integer, Some(42));
    /// ```
    pub fn pair<K, V>(key: K, value: V) -> KeyValue
    where
        K: Into<DataBlob>,
        V: Into<DataBlob>,
    {
        KeyValue {
            k: Some(key.into()),
            v: Some(value.into()),
        }
    }

    /// Creates a key-only key-value.
    ///
    /// The key is going to be equal to the given value and the key will be
    /// `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg_proto::KeyValue;
    ///
    /// let entry = KeyValue::key(String::from("quux"));
    /// assert_eq!(entry.k.unwrap().string, Some(String::from("quux")));
    /// assert_eq!(entry.v, None);
    /// ```
    pub fn key<K>(key: K) -> KeyValue
    where
        K: Into<DataBlob>,
    {
        KeyValue {
            k: Some(key.into()),
            v: None,
        }
    }
}

impl std::iter::FromIterator<KeyValue> for AttributedDict {

    fn from_iter<I>(iter: I) -> AttributedDict
    where
        I: IntoIterator<Item = KeyValue>,
    {
        AttributedDict {
            dat: iter.into_iter().collect(),
        }
    }
}

impl<K, V> std::iter::FromIterator<(K, V)> for AttributedDict
where
    K: Into<DataBlob>,
    V: Into<DataBlob>,
{
    fn from_iter<I>(iter: I) -> AttributedDict
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let pair = |(key, value)| KeyValue::pair(key, value);
        iter.into_iter().map(pair).collect()
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
