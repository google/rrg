// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod convert;
pub mod path;

pub mod v2 {
    include!(concat!(env!("OUT_DIR"), "/proto-v2/mod.rs"));
}

include!(concat!(env!("OUT_DIR"), "/proto/mod.rs"));

impl From<bool> for jobs::DataBlob {

    fn from(value: bool) -> jobs::DataBlob {
        let mut result = jobs::DataBlob::new();
        result.set_boolean(value);

        result
    }
}

impl From<i64> for jobs::DataBlob {

    fn from(value: i64) -> jobs::DataBlob {
        let mut result = jobs::DataBlob::new();
        result.set_integer(value);

        result
    }
}

impl From<f32> for jobs::DataBlob {

    fn from(value: f32) -> jobs::DataBlob {
        let mut result = jobs::DataBlob::new();
        result.set_float(value);

        result
    }
}

impl From<Vec<u8>> for jobs::DataBlob {

    fn from(value: Vec<u8>) -> jobs::DataBlob {
        let mut result = jobs::DataBlob::new();
        result.set_data(value);

        result
    }
}

impl From<String> for jobs::DataBlob {

    fn from(value: String) -> jobs::DataBlob {
        let mut result = jobs::DataBlob::new();
        result.set_string(value);

        result
    }
}

impl jobs::KeyValue {

    /// Creates a key-value pair.
    ///
    /// Both the key and the value are going to be equal to the given values.
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg_proto::jobs::KeyValue;
    ///
    /// let entry = KeyValue::pair(String::from("foo"), 42i64);
    /// assert_eq!(entry.get_k().get_string(), String::from("foo"));
    /// assert_eq!(entry.get_v().get_integer(), 42);
    /// ```
    pub fn pair<K, V>(key: K, value: V) -> jobs::KeyValue
    where
        K: Into<jobs::DataBlob>,
        V: Into<jobs::DataBlob>,
    {
        let mut result = jobs::KeyValue::new();
        result.set_k(key.into());
        result.set_v(value.into());

        result
    }

    /// Creates a key-only key-value.
    ///
    /// The key is going to be equal to the given value and the key will be
    /// `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg_proto::jobs::KeyValue;
    ///
    /// let entry = KeyValue::key(String::from("quux"));
    /// assert_eq!(entry.get_k().get_string(), String::from("quux"));
    /// assert!(!entry.has_v());
    /// ```
    pub fn key<K>(key: K) -> jobs::KeyValue
    where
        K: Into<jobs::DataBlob>,
    {
        let mut result = jobs::KeyValue::new();
        result.set_k(key.into());

        result
    }
}

impl std::iter::FromIterator<jobs::KeyValue> for jobs::AttributedDict {

    fn from_iter<I>(iter: I) -> jobs::AttributedDict
    where
        I: IntoIterator<Item = jobs::KeyValue>,
    {
        let mut result = jobs::AttributedDict::new();
        result.set_dat(iter.into_iter().collect());

        result
    }
}

impl<K, V> std::iter::FromIterator<(K, V)> for jobs::AttributedDict
where
    K: Into<jobs::DataBlob>,
    V: Into<jobs::DataBlob>,
{
    fn from_iter<I>(iter: I) -> jobs::AttributedDict
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let pair = |(key, value)| jobs::KeyValue::pair(key, value);
        iter.into_iter().map(pair).collect()
    }
}

impl crate::convert::FromLossy<std::fs::Metadata> for jobs::StatEntry {

    fn from_lossy(metadata: std::fs::Metadata) -> jobs::StatEntry {
        use rrg_macro::ack;

        let mut result = jobs::StatEntry::new();
        result.set_st_size(metadata.len());

        let atime_secs = ack! {
            metadata.accessed(),
            error: "failed to obtain file access time"
        }.and_then(|atime| ack! {
            secs(atime),
            error: "failed to convert access time to seconds"
        });
        if let Some(atime_secs) = atime_secs {
            result.set_st_atime(atime_secs);
        }

        let mtime_secs = ack! {
            metadata.modified(),
            error: "failed to obtain file modification time"
        }.and_then(|mtime| ack! {
            secs(mtime),
            error: "failed to convert modification time to seconds"
        });
        if let Some(mtime_secs) = mtime_secs {
            result.set_st_mtime(mtime_secs);
        }

        let btime_secs = ack! {
            metadata.created(),
            error: "failed to obtain file creation time"
        }.and_then(|btime| ack! {
            secs(btime),
            error: "failed to convert creation time to seconds"
        });
        if let Some(btime_secs) = btime_secs {
            result.set_st_btime(btime_secs);
        }

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::MetadataExt as _;

            let ctime_secs = ack! {
                u64::try_from(metadata.ctime()),
                error: "negative inode change time"
            };
            if let Some(ctime_secs) = ctime_secs {
                result.set_st_ctime(ctime_secs);
            }

            result.set_st_mode(metadata.mode().into());
            result.set_st_ino(metadata.ino());
            result.set_st_dev(metadata.dev());
            result.set_st_rdev(metadata.rdev());
            result.set_st_nlink(metadata.nlink());
            result.set_st_uid(metadata.uid());
            result.set_st_gid(metadata.gid());
            result.set_st_blocks(metadata.blocks());
            result.set_st_blksize(metadata.blksize());
        }

        result
    }
}

impl Into<jobs::StatEntry_ExtAttr> for ospect::fs::ExtAttr {

    fn into(self) -> jobs::StatEntry_ExtAttr {
        let mut proto = jobs::StatEntry_ExtAttr::new();

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::ffi::OsStringExt as _;
            proto.set_name(self.name.into_vec());
        }

        #[cfg(target_os = "windows")]
        {
            let name = self.name.to_string_lossy().into_owned().into_bytes();
            proto.set_name(name);
        }

        proto.set_value(self.value);

        proto
    }
}

impl TryFrom<jobs::PathSpec> for std::path::PathBuf {

    type Error = ParsePathSpecError;

    fn try_from(mut spec: jobs::PathSpec) -> Result<std::path::PathBuf, ParsePathSpecError> {
        if spec.get_pathtype() != jobs::PathSpec_PathType::OS {
            return Err(ParsePathSpecError {
                kind: ParsePathSpecErrorKind::InvalidType,
            });
        }

        let path = spec.take_path();
        if path.is_empty() {
            return Err(ParsePathSpecError {
                kind: ParsePathSpecErrorKind::Empty,
            });
        }

        Ok(std::path::PathBuf::from(path))
    }
}

impl From<std::path::PathBuf> for jobs::PathSpec {

    fn from(path: std::path::PathBuf) -> jobs::PathSpec {
        let mut result = jobs::PathSpec::new();
        result.set_path(path.to_string_lossy().into_owned());
        result.set_pathtype(jobs::PathSpec_PathType::OS);

        result
    }
}

/// An enum listing possible issues when parsing path specification.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum ParsePathSpecErrorKind {
    /// Attempted to parse an empty path.
    Empty,
    /// Attempted to parse a path of invalid type.
    InvalidType,
}

/// An error type for situations where parsing path specification failed.
#[derive(Clone, Debug)]
pub struct ParsePathSpecError {
    kind: ParsePathSpecErrorKind,
}

impl ParsePathSpecError {

    /// Describes the exact cause of the parsing failure.
    pub fn kind(&self) -> ParsePathSpecErrorKind {
        self.kind
    }
}

impl std::fmt::Display for ParsePathSpecError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParsePathSpecErrorKind::*;

        match self.kind {
            Empty => write!(fmt, "empty path"),
            InvalidType => write!(fmt, "invalid path type"),
        }
    }
}

impl std::error::Error for ParsePathSpecError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// An error type for failures that can occur when converting timestamps.
#[derive(Clone, Debug)]
pub enum TimeConversionError {
    /// Attempted to convert pre-epoch system time.
    Epoch(std::time::SystemTimeError),
    /// Attempted to convert a value outside of 64-bit unsigned integer range.
    Overflow(std::num::TryFromIntError),
}

impl TimeConversionError {

    /// Creates a conversion error from an integer overflow error.
    pub fn overflow(error: std::num::TryFromIntError) -> TimeConversionError {
        TimeConversionError::Overflow(error)
    }
}

impl std::fmt::Display for TimeConversionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use TimeConversionError::*;

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

impl std::error::Error for TimeConversionError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TimeConversionError::*;

        match *self {
            Epoch(ref error) => Some(error),
            Overflow(ref error) => Some(error),
        }
    }
}

impl From<std::time::SystemTimeError> for TimeConversionError {

    fn from(error: std::time::SystemTimeError) -> TimeConversionError {
        TimeConversionError::Epoch(error)
    }
}

/// Converts system time into epoch nanoseconds.
///
/// Some GRR messages use epoch nanoseconds for representing timestamps. In such
/// cases this function can be useful to convert from more idiomatic types.
///
/// # Examples
///
/// ```
/// use rrg_proto::nanos;
///
/// assert_eq!(nanos(std::time::UNIX_EPOCH).unwrap(), 0);
/// ```
pub fn nanos(time: std::time::SystemTime) -> Result<u64, TimeConversionError> {
    let duration = time.duration_since(std::time::UNIX_EPOCH)?;
    duration.as_nanos().try_into().map_err(TimeConversionError::overflow)
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
pub fn micros(time: std::time::SystemTime) -> Result<u64, TimeConversionError> {
    let duration = std::time::Duration::from_nanos(nanos(time)?);
    duration.as_micros().try_into().map_err(TimeConversionError::overflow)
}

/// Converts system time into epoch seconds.
///
/// Some GRR messages use epoch seconds for representing timestamps. In such
/// cases this function can be useful to convert from more idiomatic types.
///
/// # Examples
///
/// ```
/// use rrg_proto::secs;
///
/// assert_eq!(secs(std::time::UNIX_EPOCH).unwrap(), 0);
/// ```
pub fn secs(time: std::time::SystemTime) -> Result<u64, TimeConversionError> {
    let duration = std::time::Duration::from_nanos(nanos(time)?);
    Ok(duration.as_secs())
}
