// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `get_tcp_response` action.
pub struct Args {
    /// Address of the host to connect to.
    addr: std::net::SocketAddr,
    /// Timeout for establishing the connection with the host.
    connect_timeout: std::time::Duration,
    /// Timeout for writing data to the TCP stream.
    write_timeout: std::time::Duration,
    /// Timeout for reading data from the TCP stream.
    read_timeout: std::time::Duration,
    /// Data to write to the TCP stream.
    data: Vec<u8>,
}

/// Result of the `get_tcp_response` action.
pub struct Item {
    /// Data read from the TCP stream.
    data: Vec<u8>,
}

pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Read as _, Write as _};

    let mut stream = std::net::TcpStream::connect_timeout(
        &args.addr,
        args.connect_timeout,
    ).map_err(|error| Error {
        kind: ErrorKind::Connect,
        inner: error,
    })?;

    log::info!("established connection to {}", args.addr);

    stream.set_write_timeout(Some(args.write_timeout))
        .map_err(|error| Error {
            kind: ErrorKind::InvalidWriteTimeout,
            inner: error,
        })?;
    let data_write_len = stream.write(&args.data)
        .map_err(|error| Error {
            kind: ErrorKind::Write,
            inner: error,
        })?;
    stream.shutdown(std::net::Shutdown::Write)
        .map_err(|error| Error {
            kind: ErrorKind::ShutdownWrite,
            inner: error,
        })?;

    // TODO(@panhania): Charge network bytes.
    log::info!("sent {} bytes to {}", data_write_len, args.addr);

    // TODO: Limit the length of the response.
    let mut data = Vec::new();

    stream.set_read_timeout(Some(args.read_timeout))
        .map_err(|error| Error {
            kind: ErrorKind::InvalidReadTimeout,
            inner: error,
        })?;
    stream.read_to_end(&mut data)
        .map_err(|error| Error {
            kind: ErrorKind::Read,
            inner: error,
        })?;
    stream.shutdown(std::net::Shutdown::Read)
        .map_err(|error| Error {
            kind: ErrorKind::ShutdownRead,
            inner: error,
        })?;

    // TODO(@panhania): Charge network bytes.
    log::info!("received {} bytes from {}", data.len(), args.addr);

    session.reply(Item {
        data,
    })?;

    Ok(())
}

/// List of possible failure scenarios for `get_tcp_response`.
#[derive(Debug)]
enum ErrorKind {
    Connect,
    Write,
    Read,
    ShutdownWrite,
    ShutdownRead,
    InvalidWriteTimeout,
    InvalidReadTimeout,
}

/// Error type for failures specific to `get_tcp_response`.
#[derive(Debug)]
struct Error {
    kind: ErrorKind,
    inner: std::io::Error,
}

impl std::fmt::Display for ErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(fmt, "unable to connect"),
            Self::Write => write!(fmt, "unable to write to stream"),
            Self::Read => write!(fmt, "unable to read from stream"),
            Self::ShutdownWrite => write!(fmt, "failed to shutdown writing"),
            Self::ShutdownRead => write!(fmt, "failed to shutdown reading"),
            Self::InvalidWriteTimeout => write!(fmt, "invalid write timeout"),
            Self::InvalidReadTimeout => write!(fmt, "invalid read timeout"),
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind, self.inner)
    }
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

impl From<Error> for crate::session::Error {

    fn from(error: Error) -> crate::session::Error {
        crate::session::Error::action(error)
    }
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_tcp_response::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Self, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let addr = std::net::SocketAddr::try_from(proto.take_address())
            .map_err(|error| {
                ParseArgsError::invalid_field("address", error)
            })?;

        let connect_timeout = std::time::Duration::try_from(proto.take_connect_timeout())
            .map_err(|error| {
                ParseArgsError::invalid_field("connect timeout", error)
            })?;
        let write_timeout = std::time::Duration::try_from(proto.take_write_timeout())
            .map_err(|error| {
                ParseArgsError::invalid_field("write timeout", error)
            })?;
        let read_timeout = std::time::Duration::try_from(proto.take_read_timeout())
            .map_err(|error| {
                ParseArgsError::invalid_field("read timeout", error)
            })?;

        Ok(Args {
            addr,
            connect_timeout,
            write_timeout,
            read_timeout,
            data: proto.take_data(),
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_tcp_response::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::get_tcp_response::Result::new();
        proto.set_data(self.data);

        proto
    }
}
