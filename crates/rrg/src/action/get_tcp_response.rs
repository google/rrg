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
    ).unwrap(); // TODO(@panhania): Add proper error handling.

    log::info!("established connection to {}", args.addr);

    stream.set_write_timeout(Some(args.write_timeout))
        .unwrap(); // TODO(@panhania): Add proper error handling.
    let data_write_len = stream.write(&args.data)
        .unwrap(); // TODO(@panhania): Add proper error handling.
    stream.shutdown(std::net::Shutdown::Write)
        .unwrap(); // TODO(@panhania): Add proper error handling.

    // TODO(@panhania): Charge network bytes.
    log::info!("sent {} bytes to {}", data_write_len, args.addr);

    // TODO: Limit the length of the response.
    let mut data = Vec::new();

    stream.set_read_timeout(Some(args.read_timeout))
        .unwrap(); // TODO(@panhania): Add proper error handling.
    stream.read_to_end(&mut data)
        .unwrap(); // TODO(@panhania): Add proper error handling.
    stream.shutdown(std::net::Shutdown::Read)
        .unwrap(); // TODO(@panhania): Add proper error handling.

    // TODO(@panhania): Charge network bytes.
    log::info!("received {} bytes from {}", data.len(), args.addr);

    session.reply(Item {
        data,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::get_tcp_response::Args;

    fn from_proto(proto: Self::Proto) -> Result<Self, crate::request::ParseArgsError> {
        todo!()
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_tcp_response::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
