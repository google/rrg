// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod convert;
pub mod path;

use std::path::PathBuf;

use convert::FromLossy;

use rrg_macro::ack;

include!(concat!(env!("OUT_DIR"), "/grr.rs"));

pub mod protobuf {
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
        /// use rrg_proto::protobuf::jobs::KeyValue;
        ///
        /// let entry = KeyValue::pair(String::from("foo"), 42i64);
        /// assert_eq!(entry.get_k().get_string(), Some(String::from("foo")));
        /// assert_eq!(entry.get_v().get_integer(), Some(42));
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
        /// use rrg_proto::protobuf::jobs::KeyValue;
        ///
        /// let entry = KeyValue::key(String::from("quux"));
        /// assert_eq!(entry.get_k().get_string(), Some(String::from("quux")));
        /// assert_eq!(entry.has_v(), None);
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
                super::secs(atime),
                error: "failed to convert access time to seconds"
            });
            if let Some(atime_secs) = atime_secs {
                result.set_st_atime(atime_secs);
            }

            let mtime_secs = ack! {
                metadata.modified(),
                error: "failed to obtain file modification time"
            }.and_then(|mtime| ack! {
                super::secs(mtime),
                error: "failed to convert modification time to seconds"
            });
            if let Some(mtime_secs) = mtime_secs {
                result.set_st_mtime(mtime_secs);
            }

            let btime_secs = ack! {
                metadata.created(),
                error: "failed to obtain file creation time"
            }.and_then(|btime| ack! {
                super::secs(btime),
                error: "failed to convert creation time to seconds"
            });
            if let Some(btime_secs) = btime_secs {
                result.set_st_btime(btime_secs);
            }

            #[cfg(target_family = "unix")]
            {
                use std::convert::TryFrom as _;
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
}

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

impl FromLossy<std::fs::Metadata> for StatEntry {

    fn from_lossy(metadata: std::fs::Metadata) -> StatEntry {
        #[cfg(target_family = "unix")]
        use std::convert::{TryFrom, TryInto};
        #[cfg(target_family = "unix")]
        use std::os::unix::fs::MetadataExt;

        // TODO: Fix definition of `StatEntry`.
        // `StatEntry` defines insufficient integer width for some fields. For
        // now we just ignore errors, but the definition should be improved.
        #[cfg(target_family = "unix")]
        let some = |value: u64| Some(value.try_into().unwrap_or(0));

        let atime_secs = ack! {
            metadata.accessed(),
            error: "failed to obtain file access time"
        }.and_then(|atime| ack! {
            secs(atime),
            error: "failed to convert access time to seconds"
        });

        let mtime_secs = ack! {
            metadata.modified(),
            error: "failed to obtain file modification time"
        }.and_then(|mtime| ack! {
            secs(mtime),
            error: "failed to convert modification time to seconds"
        });

        let btime_secs = ack! {
            metadata.created(),
            error: "failed to obtain file creation time"
        }.and_then(|btime| ack! {
            secs(btime),
            error: "failed to convert creation time to seconds"
        });

        #[cfg(target_family = "unix")]
        let ctime_secs = ack! {
            u64::try_from(metadata.ctime()),
            error: "negative inode change time"
        };

        StatEntry {
            #[cfg(target_family = "unix")]
            st_mode: Some(metadata.mode().into()),
            #[cfg(target_family = "unix")]
            st_ino: some(metadata.ino()),
            #[cfg(target_family = "unix")]
            st_dev: some(metadata.dev()),
            #[cfg(target_family = "unix")]
            st_rdev: some(metadata.rdev()),
            #[cfg(target_family = "unix")]
            st_nlink: some(metadata.nlink()),
            #[cfg(target_family = "unix")]
            st_uid: Some(metadata.uid()),
            #[cfg(target_family = "unix")]
            st_gid: Some(metadata.gid()),
            st_size: Some(metadata.len()),
            st_atime: atime_secs,
            st_mtime: mtime_secs,
            #[cfg(target_family = "unix")]
            st_ctime: ctime_secs,
            st_btime: btime_secs,
            #[cfg(target_family = "unix")]
            st_blocks: some(metadata.blocks()),
            #[cfg(target_family = "unix")]
            st_blksize: some(metadata.blksize()),
            ..Default::default()
        }
    }
}

/// An error type for situations where parsing path specification failed.
#[derive(Clone, Debug)]
pub enum ParsePathSpecError {
    /// Attempted to parse an empty path.
    Empty,
    /// Attempted to parse a path of unknown type.
    UnknownType(i32),
    /// Attempted to parse a path of invalid type.
    InvalidType(path_spec::PathType),
}

impl std::fmt::Display for ParsePathSpecError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParsePathSpecError::*;

        match *self {
            Empty => {
                write!(fmt, "empty path")
            }
            UnknownType(value) => {
                write!(fmt, "unknown path type value: {}", value)
            }
            InvalidType(value) => {
                write!(fmt, "invalid path type: {:?}", value)
            }
        }
    }
}

impl std::error::Error for ParsePathSpecError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::TryFrom<PathSpec> for PathBuf {

    type Error = ParsePathSpecError;

    fn try_from(spec: PathSpec) -> Result<PathBuf, ParsePathSpecError> {
        use ParsePathSpecError::*;

        let path_type = spec.pathtype.unwrap_or_default();
        match path_spec::PathType::from_i32(path_type) {
            Some(path_spec::PathType::Os) => (),
            Some(path_type) => return Err(InvalidType(path_type)),
            None => return Err(UnknownType(path_type)),
        };

        match spec.path {
            Some(path) if path.len() > 0 => Ok(PathBuf::from(path)),
            _ => Err(ParsePathSpecError::Empty),
        }
    }
}

impl From<PathBuf> for PathSpec {

    fn from(path: PathBuf) -> PathSpec {
        PathSpec {
            path: Some(path.to_string_lossy().into_owned()),
            pathtype: Some(path_spec::PathType::Os.into()),
            ..Default::default()
        }
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
    use std::convert::TryInto as _;

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
    use std::convert::TryInto as _;

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
