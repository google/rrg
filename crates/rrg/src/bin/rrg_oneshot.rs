// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Developer command to run a Fleetspeakless one-shot RRG action.
//!
//! e.g. you may run an action as root with:
//! ```text
//! cargo build && (protoc --proto_path=proto/ --encode=rrg.Request proto/rrg.proto proto/rrg/action/*.proto | sudo -A ./target/debug/rrg_oneshot) <<EOF
//! action: GET_FILESYSTEM_TIMELINE_TSK
//! args {
//!   [type.googleapis.com/rrg.action.get_filesystem_timeline_tsk.Args] {
//!     root: {
//!         raw_bytes: "/mnt/foo/bar"
//!     }
//!   }
//! }
//! EOF
//! ```
use protobuf::Message as _;

struct OneshotSession {
    args: rrg::args::Args,
}

impl OneshotSession {
    /// Constructs a new fake session with test default agent arguments.
    pub fn new() -> Self {
        Self::with_args(rrg::args::Args {
            heartbeat_rate: std::time::Duration::from_secs(0),
            ping_rate: std::time::Duration::from_secs(0),
            command_verification_key: None,
            verbosity: log::LevelFilter::Debug,
            log_to_stdout: false,
            log_to_file: None,
        })
    }

    /// Constructs a new fake session with the given agent arguments.
    pub fn with_args(args: rrg::args::Args) -> Self {
        Self { args }
    }
}

impl rrg::session::Session for OneshotSession {
    fn args(&self) -> &rrg::args::Args {
        &self.args
    }

    fn reply<I>(&mut self, item: I) -> rrg::session::Result<()>
    where
        I: rrg::Item + 'static,
    {
        println!(
            "Reply: {}",
            protobuf::text_format::print_to_string_pretty(&item.into_proto())
        );
        Ok(())
    }

    fn send<I>(&mut self, sink: rrg::Sink, item: I) -> rrg::session::Result<()>
    where
        I: rrg::Item + 'static,
    {
        println!(
            "Sent to {sink:?}: {}",
            protobuf::text_format::print_to_string_pretty(&item.into_proto())
        );
        Ok(())
    }

    fn heartbeat(&mut self) {}
}

fn main() {
    // rust-protobuf does not support Any in text or JSON formats, so we're
    // stuck taking in encoded protobufs.
    // See https://github.com/stepancheg/rust-protobuf/issues/628
    let request_proto = rrg_proto::rrg::Request::parse_from_reader(&mut std::io::stdin())
        .expect("Failed to parse request protobuf");
    let request = rrg::Request::try_from(request_proto).expect("Failed to parse request");
    let mut session = OneshotSession::new();
    rrg::action::dispatch(&mut session, request).unwrap();
}
