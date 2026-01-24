// Copyright 2026 Google LLC
#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::FuzzSession;
use rrg::action::get_tcp_response;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;
use arbitrary::Arbitrary;
use std::net::TcpListener;
use std::thread;
use std::io::{Read, Write};
use std::sync::mpsc;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    server_response: Vec<u8>,
    agent_data: Vec<u8>,
    connect_timeout_ns: u32,
    write_timeout_ns: u32,
    read_timeout_ns: u32,
    // If true, send >1MB to trigger the "limit reached" path
    flood_server: bool,
}

fuzz_target!(|input: FuzzInput| {
    let (tx, rx) = mpsc::channel();
    let response_data = input.server_response.clone();
    let should_flood = input.flood_server;

    let _handle = thread::spawn(move || {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => {
                let _ = tx.send(None);
                return;
            }
        };

        if let Ok(addr) = listener.local_addr() {
            let _ = tx.send(Some(addr));
        }

        if let Ok((mut stream, _)) = listener.accept() {
            // Read whatever the agent sends
            let mut buf = [0u8; 128];
            let _ = stream.read(&mut buf);

            if should_flood {
                // Send 1.1 MB to force the client's 'take(1MB)' limit
                // This keeps the connection OPEN when read_to_end returns.
                let chunk = [b'A'; 4096];
                // 270 * 4096 > 1MB
                for _ in 0..270 {
                    if stream.write_all(&chunk).is_err() {
                        break;
                    }
                }
            } else {
                // Standard small response
                let _ = stream.write_all(&response_data);
            }
        }
    });

    let server_addr = match rx.recv() {
        Ok(Some(addr)) => addr,
        _ => return,
    };

    let mut session = FuzzSession::new();

    let mut args = rrg_proto::get_tcp_response::Args::new();
    let mut proto_addr = rrg_proto::net::SocketAddress::new();
    proto_addr.set_ip_address(server_addr.ip().into());
    proto_addr.set_port(server_addr.port() as u32);
    args.set_address(proto_addr);

    args.set_data(input.agent_data);

    fn make_duration(nanos: u32) -> protobuf::well_known_types::duration::Duration {
        let mut d = protobuf::well_known_types::duration::Duration::new();
        d.nanos = (nanos % 50_000_000) as i32;
        d.seconds = 0;
        d
    }

    args.set_connect_timeout(make_duration(input.connect_timeout_ns));
    args.set_write_timeout(make_duration(input.write_timeout_ns));
    args.set_read_timeout(make_duration(input.read_timeout_ns));

    let mut proto = RequestProto::new();
    proto.set_request_id(404);
    proto.set_action(rrg_proto::rrg::Action::GET_TCP_RESPONSE);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            let _ = get_tcp_response::handle(&mut session, internal_args);
        }
    }
});
