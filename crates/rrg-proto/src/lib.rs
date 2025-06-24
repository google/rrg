// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod convert;
pub mod path;

include!(concat!(env!("OUT_DIR"), "/proto/mod.rs"));

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

impl From<std::fs::FileType> for fs::file_metadata::Type {

    fn from(file_type: std::fs::FileType) -> fs::file_metadata::Type {
        match () {
            _ if file_type.is_file() => fs::file_metadata::Type::FILE,
            _ if file_type.is_dir() => fs::file_metadata::Type::DIR,
            _ if file_type.is_symlink() => fs::file_metadata::Type::SYMLINK,
            _ => fs::file_metadata::Type::UNKNOWN,
        }
    }
}

impl From<std::fs::Metadata> for fs::FileMetadata {

    fn from(metadata: std::fs::Metadata) -> fs::FileMetadata {
        let mut proto = fs::FileMetadata::default();
        proto.set_type(metadata.file_type().into());
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

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::MetadataExt as _;

            proto.set_unix_dev(metadata.dev());
            proto.set_unix_ino(metadata.ino());
            proto.set_unix_mode(metadata.mode());
            proto.set_unix_nlink(metadata.nlink());
            proto.set_unix_uid(metadata.uid());
            proto.set_unix_gid(metadata.gid());
            proto.set_unix_rdev(metadata.rdev());
            proto.set_unix_blksize(metadata.blksize());
            proto.set_unix_blocks(metadata.blocks());
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

impl TryFrom<net::IpAddress> for std::net::IpAddr {

    type Error = ParseIpAddrError;

    fn try_from(proto: net::IpAddress) -> Result<std::net::IpAddr, Self::Error> {
        if let Ok(octets) = <[u8; 4]>::try_from(&proto.octets[..]) {
            return Ok(std::net::IpAddr::from(octets));
        }
        if let Ok(octets) = <[u8; 16]>::try_from(&proto.octets[..]) {
            return Ok(std::net::IpAddr::from(octets));
        }

        Err(ParseIpAddrError {
            octets_len: proto.octets.len(),
        })
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

impl TryFrom<net::SocketAddress> for std::net::SocketAddr {

    type Error = ParseSocketAddrError;

    fn try_from(mut proto: net::SocketAddress) -> Result<std::net::SocketAddr, Self::Error> {
        let addr = std::net::IpAddr::try_from(proto.take_ip_address())
            .map_err(ParseSocketAddrError::InvalidIpAddr)?;
        let port = u16::try_from(proto.port)
            .map_err(|_| ParseSocketAddrError::PortOutOfRange {
                port: proto.port,
            })?;

        Ok(std::net::SocketAddr::from((addr, port)))
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

#[cfg(target_os = "windows")]
impl From<::winreg::PredefinedKey> for self::winreg::PredefinedKey {

    fn from(key: ::winreg::PredefinedKey) -> self::winreg::PredefinedKey {
        use self::winreg::PredefinedKey::*;

        match key {
            ::winreg::PredefinedKey::ClassesRoot => CLASSES_ROOT,
            ::winreg::PredefinedKey::CurrentConfig => CURRENT_CONFIG,
            ::winreg::PredefinedKey::CurrentUser => CURRENT_USER,
            ::winreg::PredefinedKey::CurrentUserLocalSettings => CURRENT_USER_LOCAL_SETTINGS,
            ::winreg::PredefinedKey::LocalMachine => LOCAL_MACHINE,
            ::winreg::PredefinedKey::PerformanceData => PERFORMANCE_DATA,
            ::winreg::PredefinedKey::PerformanceNlstext => PERFORMANCE_NLSTEXT,
            ::winreg::PredefinedKey::PerformanceText => PERFORMANCE_TEXT,
            ::winreg::PredefinedKey::Users => USERS,
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<self::winreg::PredefinedKey> for ::winreg::PredefinedKey {

    type Error = ParseWinregPredefinedKeyError;

    fn try_from(key: self::winreg::PredefinedKey) -> Result<::winreg::PredefinedKey, ParseWinregPredefinedKeyError> {
        use self::winreg::PredefinedKey::*;

        match key {
            CLASSES_ROOT => Ok(::winreg::PredefinedKey::ClassesRoot),
            CURRENT_USER => Ok(::winreg::PredefinedKey::CurrentUser),
            LOCAL_MACHINE => Ok(::winreg::PredefinedKey::LocalMachine),
            USERS => Ok(::winreg::PredefinedKey::Users),
            PERFORMANCE_DATA => Ok(::winreg::PredefinedKey::PerformanceData),
            CURRENT_CONFIG => Ok(::winreg::PredefinedKey::CurrentConfig),
            PERFORMANCE_TEXT => Ok(::winreg::PredefinedKey::PerformanceText),
            PERFORMANCE_NLSTEXT => Ok(::winreg::PredefinedKey::PerformanceNlstext),
            CURRENT_USER_LOCAL_SETTINGS => Ok(::winreg::PredefinedKey::CurrentUserLocalSettings),
            _ => Err(ParseWinregPredefinedKeyError {
                value: protobuf::Enum::value(&key),
            }),
        }
    }
}

#[cfg(target_os = "windows")]
impl From<::winreg::Value> for self::winreg::Value {

    fn from(value: ::winreg::Value) -> self::winreg::Value {
        let mut proto = self::winreg::Value::default();
        proto.set_name(value.name.to_string_lossy().into_owned());

        match value.data {
            ::winreg::ValueData::None => {},
            ::winreg::ValueData::Bytes(bytes) => {
                proto.set_bytes(bytes);
            }
            ::winreg::ValueData::String(string) => {
                proto.set_string(string.to_string_lossy().into_owned());
            }
            ::winreg::ValueData::ExpandString(string) => {
                proto.set_expand_string(string.to_string_lossy().into_owned());
            }
            ::winreg::ValueData::MultiString(strings) => {
                let strings = strings.into_iter()
                    .map(|string| string.to_string_lossy().into_owned())
                    .collect();

                proto.mut_multi_string().set_values(strings);
            }
            ::winreg::ValueData::Link(string) => {
                proto.set_link(string.to_string_lossy().into_owned());
            }
            ::winreg::ValueData::U32(int) => {
                proto.set_uint32(int);
            }
            ::winreg::ValueData::U64(int) => {
                proto.set_uint64(int);
            }
        }

        proto
    }
}

impl From<rrg::log::Level> for log::LevelFilter {

    fn from(level: rrg::log::Level) -> log::LevelFilter {
        match level {
            rrg::log::Level::UNSET => log::LevelFilter::Off,
            rrg::log::Level::ERROR => log::LevelFilter::Error,
            rrg::log::Level::WARN => log::LevelFilter::Warn,
            rrg::log::Level::INFO => log::LevelFilter::Info,
            rrg::log::Level::DEBUG => log::LevelFilter::Debug,
        }
    }
}

impl From<log::Level> for rrg::log::Level {

    fn from(level: log::Level) -> rrg::log::Level {
        match level {
            log::Level::Error => rrg::log::Level::ERROR,
            log::Level::Warn => rrg::log::Level::WARN,
            log::Level::Info => rrg::log::Level::INFO,
            log::Level::Debug => rrg::log::Level::DEBUG,
            log::Level::Trace => rrg::log::Level::DEBUG,
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

/// Error that can occur when parsing IP addresses.
#[derive(Debug)]
pub struct ParseIpAddrError {
    octets_len: usize,
}

impl std::fmt::Display for ParseIpAddrError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "invalid length of octets: {}", self.octets_len)
    }
}

impl std::error::Error for ParseIpAddrError {
}

/// Error that can occur when parsing socket addresses.
#[derive(Debug)]
pub enum ParseSocketAddrError {
    InvalidIpAddr(ParseIpAddrError),
    PortOutOfRange {
        port: u32,
    },
}

impl std::fmt::Display for ParseSocketAddrError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidIpAddr(error) => {
                write!(fmt, "invalid IP address: {error}")
            }
            Self::PortOutOfRange { port } => {
                write!(fmt, "port out of range: {port}")
            }
        }
    }
}

impl std::error::Error for ParseSocketAddrError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidIpAddr(error) => Some(error),
            Self::PortOutOfRange { .. } => None,
        }
    }
}

#[cfg(target_os = "windows")]
/// Error that can occur when parsing predefined registry keys.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseWinregPredefinedKeyError {
    pub value: i32,
}

#[cfg(target_os = "windows")]
impl std::fmt::Display for ParseWinregPredefinedKeyError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "invalid Windows Registry predefined key: {}", self.value)
    }
}

#[cfg(target_os = "windows")]
impl std::error::Error for ParseWinregPredefinedKeyError {
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
pub fn into_timestamp(time: std::time::SystemTime) -> protobuf::well_known_types::timestamp::Timestamp {
    let since_epoch = time.duration_since(std::time::UNIX_EPOCH)
        .expect("pre-epoch time");

    let mut proto = protobuf::well_known_types::timestamp::Timestamp::default();
    proto.nanos = since_epoch.subsec_nanos() as i32;
    proto.seconds = since_epoch.as_secs() as i64;

    proto
}

/// Converts a protobuf [`Duration`] message to [`std::time::Duration`].
///
/// [`Duration`]: protobuf::well_known_types::Duration
///
/// # Examples
///
/// ```
/// let mut proto = protobuf::well_known_types::duration::Duration::default();
/// proto.seconds = 123;
/// proto.nanos = 456789000;
///
/// let duration = rrg_proto::try_from_duration(proto)
///     .unwrap();
/// assert_eq!(duration, std::time::Duration::from_micros(123456789));
/// ```
///
/// ```
/// let mut proto = protobuf::well_known_types::duration::Duration::default();
/// proto.seconds = -1337;
///
/// let error = rrg_proto::try_from_duration(proto)
///     .unwrap_err();
/// assert_eq!(error.kind(), rrg_proto::ParseDurationErrorKind::NegativeSecs);
/// ```
pub fn try_from_duration(
    duration: protobuf::well_known_types::duration::Duration,
) -> Result<std::time::Duration, ParseDurationError>
{
    let secs = u64::try_from(duration.seconds)
        .map_err(|_| ParseDurationError {
            kind: ParseDurationErrorKind::NegativeSecs,
        })?;

    let nanos = u64::try_from(duration.nanos)
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

#[cfg(test)]
mod tests {

    #[cfg(target_os = "windows")]
    #[test]
    fn try_from_winreg_predefined_key_all_covered() {
        use protobuf::Enum as _;

        for value in super::winreg::PredefinedKey::VALUES {
            // `UNKNOWN` is the only value we expect not to parse.
            if *value == super::winreg::PredefinedKey::UNKNOWN {
                continue;
            }

            assert!(::winreg::PredefinedKey::try_from(*value).is_ok());
        }
    }
}
