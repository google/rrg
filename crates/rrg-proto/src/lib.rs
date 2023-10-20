// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod convert;
pub mod path;

pub mod v2 {
    include!(concat!(env!("OUT_DIR"), "/proto-v2/mod.rs"));

    impl From<ospect::os::Kind> for os::Type {

        fn from(kind: ospect::os::Kind) -> os::Type {
            match kind {
                ospect::os::Kind::Linux => os::Type::LINUX,
                ospect::os::Kind::Macos => os::Type::MACOS,
                ospect::os::Kind::Windows => os::Type::WINDOWS,
            }
        }
    }

    impl From<std::path::PathBuf> for fs::Path {

        fn from(path: std::path::PathBuf) -> fs::Path {
            let mut proto = fs::Path::default();
            proto.set_raw_bytes(crate::path::into_bytes(path));

            proto
        }
    }


    impl TryFrom<fs::Path> for std::path::PathBuf {

        type Error = ParsePathError;

        fn try_from(mut proto: fs::Path) -> Result<std::path::PathBuf, ParsePathError> {
            crate::path::from_bytes(proto.take_raw_bytes())
                .map_err(ParsePathError)
        }
    }

    impl From<std::fs::FileType> for fs::FileMetadata_Type {

        fn from(file_type: std::fs::FileType) -> fs::FileMetadata_Type {
            match () {
                _ if file_type.is_file() => fs::FileMetadata_Type::FILE,
                _ if file_type.is_dir() => fs::FileMetadata_Type::DIR,
                _ if file_type.is_symlink() => fs::FileMetadata_Type::SYMLINK,
                _ => fs::FileMetadata_Type::UNKNOWN,
            }
        }
    }

    impl From<std::fs::Metadata> for fs::FileMetadata {

        fn from(metadata: std::fs::Metadata) -> fs::FileMetadata {
            use crate::into_timestamp;

            let mut proto = fs::FileMetadata::default();
            proto.set_field_type(metadata.file_type().into());
            proto.set_size(metadata.len());

            match metadata.accessed() {
                Ok(time) => proto.set_access_time(into_timestamp(time)),
                Err(_) => (), // TODO(@panhania): Consider logging.
            }
            match metadata.modified() {
                Ok(time) => proto.set_modification_time(into_timestamp(time)),
                Err(_) => (), // TODO(@panhania): Consider logging.
            }
            match metadata.created() {
                Ok(time) => proto.set_creation_time(into_timestamp(time)),
                Err(_) => (), // TODO(@panhania): Consider logging.
            }

            proto
        }
    }

    impl From<ospect::fs::ExtAttr> for fs::FileExtAttr {

        fn from(ext_attr: ospect::fs::ExtAttr) -> fs::FileExtAttr {
            let mut proto = fs::FileExtAttr::default();
            proto.set_value(ext_attr.value);

            #[cfg(target_family = "unix")]
            {
                use std::os::unix::ffi::OsStringExt as _;
                proto.set_name(ext_attr.name.into_vec());
            }

            // Extended attributes are not supported on Windows, so technically
            // we don't need to have this code. But in case somebody creates an
            // aritficial extended attribute code it is better to be at least
            // somewhat covered.
            #[cfg(target_family = "windows")]
            {
                let name_str = ext_attr.name.to_string_lossy();
                proto.set_name(name_str.as_bytes().into());
            }

            proto
        }
    }

    impl From<ospect::fs::Mount> for fs::Mount {

        fn from(mount: ospect::fs::Mount) -> fs::Mount {
            let mut proto = fs::Mount::default();
            proto.set_name(mount.name);
            proto.set_path(mount.path.into());
            proto.set_fs_type(mount.fs_type);

            proto
        }
    }

    impl From<std::net::Ipv4Addr> for net::IpAddress {

        fn from(addr: std::net::Ipv4Addr) -> net::IpAddress {
            let mut proto = net::IpAddress::default();
            proto.set_octets(Vec::from(addr.octets()));

            proto
        }
    }

    impl From<std::net::Ipv6Addr> for net::IpAddress {

        fn from(addr: std::net::Ipv6Addr) -> net::IpAddress {
            let mut proto = net::IpAddress::default();
            proto.set_octets(Vec::from(addr.octets()));

            proto
        }
    }

    impl From<std::net::IpAddr> for net::IpAddress {

        fn from(addr: std::net::IpAddr) -> net::IpAddress {
            match addr {
                std::net::IpAddr::V4(addr) => addr.into(),
                std::net::IpAddr::V6(addr) => addr.into(),
            }
        }
    }

    impl From<std::net::SocketAddrV4> for net::SocketAddress {

        fn from(addr: std::net::SocketAddrV4) -> net::SocketAddress {
            let mut proto = net::SocketAddress::default();
            proto.set_ip_address(net::IpAddress::from(*addr.ip()));
            proto.set_port(u32::from(addr.port()));

            proto
        }
    }

    impl From<std::net::SocketAddrV6> for net::SocketAddress {

        fn from(addr: std::net::SocketAddrV6) -> net::SocketAddress {
            let mut proto = net::SocketAddress::default();
            proto.set_ip_address(net::IpAddress::from(*addr.ip()));
            proto.set_port(u32::from(addr.port()));

            proto
        }
    }

    impl From<std::net::SocketAddr> for net::SocketAddress {

        fn from(addr: std::net::SocketAddr) -> net::SocketAddress {
            match addr {
                std::net::SocketAddr::V4(addr) => addr.into(),
                std::net::SocketAddr::V6(addr) => addr.into(),
            }
        }
    }

    impl From<ospect::net::MacAddr> for net::MacAddress {

        fn from(addr: ospect::net::MacAddr) -> net::MacAddress {
            let mut proto = net::MacAddress::default();
            proto.set_octets(Vec::from(addr.octets()));

            proto
        }
    }

    impl From<ospect::net::TcpState> for net::TcpState {

        fn from(state: ospect::net::TcpState) -> net::TcpState {
            use ospect::net::TcpState::*;
            match state {
                Listen => net::TcpState::LISTEN,
                SynSent => net::TcpState::SYN_SENT,
                SynReceived => net::TcpState::SYN_RECEIVED,
                Established => net::TcpState::ESTABLISHED,
                FinWait1 => net::TcpState::FIN_WAIT_1,
                FinWait2 => net::TcpState::FIN_WAIT_2,
                CloseWait => net::TcpState::CLOSE_WAIT,
                Closing => net::TcpState::CLOSING,
                LastAck => net::TcpState::LAST_ACK,
                TimeWait => net::TcpState::TIME_WAIT,
                Closed => net::TcpState::CLOSED,
            }
        }
    }

    impl From<ospect::net::TcpConnectionV4> for net::TcpConnection {

        fn from(conn: ospect::net::TcpConnectionV4) -> net::TcpConnection {
            let mut proto = net::TcpConnection::default();
            proto.set_pid(conn.pid());
            proto.set_local_address(conn.local_addr().into());
            proto.set_remote_address(conn.remote_addr().into());
            proto.set_state(conn.state().into());

            proto
        }
    }

    impl From<ospect::net::TcpConnectionV6> for net::TcpConnection {

        fn from(conn: ospect::net::TcpConnectionV6) -> net::TcpConnection {
            let mut proto = net::TcpConnection::default();
            proto.set_pid(conn.pid());
            proto.set_local_address(conn.local_addr().into());
            proto.set_remote_address(conn.remote_addr().into());
            proto.set_state(conn.state().into());

            proto
        }
    }

    impl From<ospect::net::TcpConnection> for net::TcpConnection {

        fn from(conn: ospect::net::TcpConnection) -> net::TcpConnection {
            match conn {
                ospect::net::TcpConnection::V4(conn) => conn.into(),
                ospect::net::TcpConnection::V6(conn) => conn.into(),
            }
        }
    }

    impl From<ospect::net::UdpConnectionV4> for net::UdpConnection {

        fn from(conn: ospect::net::UdpConnectionV4) -> net::UdpConnection {
            let mut proto = net::UdpConnection::default();
            proto.set_pid(conn.pid());
            proto.set_local_address(conn.local_addr().into());

            proto
        }
    }

    impl From<ospect::net::UdpConnectionV6> for net::UdpConnection {

        fn from(conn: ospect::net::UdpConnectionV6) -> net::UdpConnection {
            let mut proto = net::UdpConnection::default();
            proto.set_pid(conn.pid());
            proto.set_local_address(conn.local_addr().into());

            proto
        }
    }

    impl From<ospect::net::UdpConnection> for net::UdpConnection {

        fn from(conn: ospect::net::UdpConnection) -> net::UdpConnection {
            match conn {
                ospect::net::UdpConnection::V4(conn) => conn.into(),
                ospect::net::UdpConnection::V6(conn) => conn.into(),
            }
        }
    }

    impl From<ospect::net::Connection> for net::Connection {

        fn from(conn: ospect::net::Connection) -> net::Connection {
            let mut proto = net::Connection::default();
            match conn {
                ospect::net::Connection::Tcp(conn) => {
                    proto.set_tcp(conn.into());
                }
                ospect::net::Connection::Udp(conn) => {
                    proto.set_udp(conn.into());
                }
            }

            proto
        }
    }

    impl From<ospect::net::Interface> for net::Interface {

        fn from(iface: ospect::net::Interface) -> net::Interface {
            let mut proto = net::Interface::default();
            proto.set_name(iface.name().to_string_lossy().into_owned());

            if let Some(mac_addr) = iface.mac_addr() {
                proto.set_mac_address((*mac_addr).into());
            }

            let ip_addrs = iface.ip_addrs()
                .map(|ip_addr| net::IpAddress::from(*ip_addr))
                .collect::<Vec<_>>();
            proto.set_ip_addresses(ip_addrs.into());

            proto
        }
    }

    impl From<rrg::Log_Level> for log::LevelFilter {

        fn from(level: rrg::Log_Level) -> log::LevelFilter {
            match level {
               rrg::Log_Level::UNSET => log::LevelFilter::Off,
               rrg::Log_Level::ERROR => log::LevelFilter::Error,
               rrg::Log_Level::WARN => log::LevelFilter::Warn,
               rrg::Log_Level::INFO => log::LevelFilter::Info,
               rrg::Log_Level::DEBUG => log::LevelFilter::Debug,
            }
        }
    }

    impl From<log::Level> for rrg::Log_Level {

        fn from(level: log::Level) -> rrg::Log_Level {
            match level {
                log::Level::Error => rrg::Log_Level::ERROR,
                log::Level::Warn => rrg::Log_Level::WARN,
                log::Level::Info => rrg::Log_Level::INFO,
                log::Level::Debug => rrg::Log_Level::DEBUG,
                log::Level::Trace => rrg::Log_Level::DEBUG,
            }
        }
    }

    /// A type representing errors that can occur when parsing paths.
    #[derive(Debug, PartialEq, Eq)]
    pub struct ParsePathError(crate::path::ParseError);

    impl std::fmt::Display for ParsePathError {

        fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
            self.0.fmt(fmt)
        }
    }

    impl std::error::Error for ParsePathError {

        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.0.source()
        }
    }
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

// TODO(@panhania): Upgrade to version 3.2.0 of `protobuf` that supports
// `From<SystemTime>` conversion of Protocol Buffers `Timestamp`.
/// Converts [`SystemTime`] to a Protocol Buffers `Timestamp` message.
///
/// # Examples
///
/// ```
/// let timestamp = rrg_proto::into_timestamp(std::time::SystemTime::now());
/// assert!(timestamp.seconds > 0);
/// ```
pub fn into_timestamp(time: std::time::SystemTime) -> protobuf::well_known_types::Timestamp {
    let since_epoch = time.duration_since(std::time::UNIX_EPOCH)
        .expect("pre-epoch time");

    let mut proto = protobuf::well_known_types::Timestamp::default();
    proto.set_nanos(since_epoch.subsec_nanos() as i32);
    proto.set_seconds(since_epoch.as_secs() as i64);

    proto
}

/// Converts a protobuf [`Duration`] message to [`std::time::Duration`].
///
/// [`Duration`]: protobuf::well_known_types::Duration
///
/// # Examples
///
/// ```
/// let mut proto = protobuf::well_known_types::Duration::default();
/// proto.set_seconds(123);
/// proto.set_nanos(456789000);
///
/// let duration = rrg_proto::try_from_duration(proto)
///     .unwrap();
/// assert_eq!(duration, std::time::Duration::from_micros(123456789));
/// ```
///
/// ```
/// let mut proto = protobuf::well_known_types::Duration::default();
/// proto.set_seconds(-1337);
///
/// let error = rrg_proto::try_from_duration(proto)
///     .unwrap_err();
/// assert_eq!(error.kind(), rrg_proto::ParseDurationErrorKind::NegativeSecs);
/// ```
pub fn try_from_duration(
    duration: protobuf::well_known_types::Duration,
) -> Result<std::time::Duration, ParseDurationError>
{
    let secs = u64::try_from(duration.get_seconds())
        .map_err(|_| ParseDurationError {
            kind: ParseDurationErrorKind::NegativeSecs,
        })?;

    let nanos = u64::try_from(duration.get_nanos())
        .map_err(|_| ParseDurationError {
            kind: ParseDurationErrorKind::NegativeNanos,
        })?;

    let duration_secs = std::time::Duration::from_secs(secs);
    let duration_nanos = std::time::Duration::from_nanos(nanos);
    Ok(duration_secs + duration_nanos)
}

/// Error type for cases when parsing a protobuf [`Duration`] messages.
///
/// [`Duration`]: protobuf::well_known_types::Duration
#[derive(Debug, Clone)]
pub struct ParseDurationError {
    /// A corresponding [`ParseDurationErrorKind`] of the error.
    kind: ParseDurationErrorKind,
}

impl ParseDurationError {

    /// Returns the corresponding [`ParseDurationErrorKind`] of this error.
    pub fn kind(&self) -> ParseDurationErrorKind {
        self.kind
    }
}

impl std::fmt::Display for ParseDurationError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseDurationErrorKind::*;
        match self.kind {
            NegativeSecs => write!(fmt, "negative seconds"),
            NegativeNanos => write!(fmt, "negative nanoseconds"),
        }
    }
}

impl std::error::Error for ParseDurationError {
}

/// Kinds of errors that can happen when parsing protobuf [`Duration`] messages.
///
/// [`Duration`]: protobuf::well_known_types::Duration
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum ParseDurationErrorKind {
    /// Value of the `seconds` field was negative.
    NegativeSecs,
    /// Value of the `nanos` field was negative.
    NegativeNanos,
}
