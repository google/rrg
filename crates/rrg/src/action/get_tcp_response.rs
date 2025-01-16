// Copyright 2025 Google LLC
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

    let mut data = Vec::new();

    stream.set_read_timeout(Some(args.read_timeout))
        .map_err(|error| Error {
            kind: ErrorKind::InvalidReadTimeout,
            inner: error,
        })?;
    // We limit the number of bytes read to 1 MiB. Fleetspeak does not allow for
    // messages bigger than 2 MiB anyway.
    //
    // In the future we might lift this restriction by sending multiple results.
    // We can then either depend on the default session network byte limit or
    // introduce a separate argument to prevent flooding the server in case of
    // rogue or invalid TCP server.
    let mut limited_stream = stream.take(1 * 1024 * 1024);
    limited_stream.read_to_end(&mut data)
        .map_err(|error| Error {
            kind: ErrorKind::Read,
            inner: error,
        })?;
    stream = limited_stream.into_inner();
    match stream.shutdown(std::net::Shutdown::Read) {
        Ok(()) => (),
        // It is possible that the server disconnected at this point, we do not
        // consider this to be an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => (),
        Err(error) => return Err(Error {
            kind: ErrorKind::ShutdownRead,
            inner: error,
        }.into()),
    }

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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_empty_request_data() {
        let (addr_sender, addr_receiver) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || {
            use std::io::Write as _;

            let server = std::net::TcpListener::bind(
                (std::net::Ipv4Addr::LOCALHOST, 0),
            ).unwrap();

            addr_sender.send(server.local_addr().unwrap())
                .unwrap();

            let (mut stream, _) = server.accept()
                .unwrap();
            stream.write(b"foobar")
                .unwrap();
            stream.flush()
                .unwrap();
        });

        let args = Args {
            addr: addr_receiver.recv().unwrap(),
            connect_timeout: std::time::Duration::from_secs(1),
            write_timeout: std::time::Duration::from_secs(1),
            read_timeout: std::time::Duration::from_secs(1),
            data: vec![],
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.reply::<Item>(0).data, b"foobar");
    }

    #[test]
    fn handle_non_empty_request_data() {
        let (addr_sender, addr_receiver) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let server = std::net::TcpListener::bind(
                (std::net::Ipv4Addr::LOCALHOST, 0),
            ).unwrap();

            addr_sender.send(server.local_addr().unwrap())
                .unwrap();

            let (mut stream, _) = server.accept()
                .unwrap();

            let mut buf = [0; 3];
            stream.read_exact(&mut buf)
                .unwrap();
            assert_eq!(&buf[..], b"foo");

            stream.write(b"bar")
                .unwrap();
            stream.flush()
                .unwrap();
        });

        let args = Args {
            addr: addr_receiver.recv().unwrap(),
            connect_timeout: std::time::Duration::from_secs(1),
            write_timeout: std::time::Duration::from_secs(1),
            read_timeout: std::time::Duration::from_secs(1),
            data: b"foo".to_vec(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.reply::<Item>(0).data, b"bar");
    }

    #[test]
    fn handle_response_over_limit() {
        let (addr_sender, addr_receiver) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || {
            use std::io::Write as _;

            let server = std::net::TcpListener::bind(
                (std::net::Ipv4Addr::LOCALHOST, 0),
            ).unwrap();

            addr_sender.send(server.local_addr().unwrap())
                .unwrap();

            let (mut stream, _) = server.accept()
                .unwrap();

            let data = vec![0xF0; 3 * 1024 * 1024]; // 3 MiB.
            std::io::copy(&mut data.as_slice(), &mut stream)
                .unwrap();
            stream.flush()
                .unwrap();
        });

        let args = Args {
            addr: addr_receiver.recv().unwrap(),
            connect_timeout: std::time::Duration::from_secs(1),
            write_timeout: std::time::Duration::from_secs(1),
            read_timeout: std::time::Duration::from_secs(1),
            data: vec![],
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);
        assert_eq!(session.reply::<Item>(0).data, vec![0xF0; 1 * 1024 * 1024]);
    }

    // Unfortunately, seems like (at least on Linux) timeouts have at least a
    // second granularity, so in order to test them we would have to wait for at
    // least a second which is too slow for a unit test.
}
