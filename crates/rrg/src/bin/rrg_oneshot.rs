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

struct OneshotSession {
    args: rrg::args::Args,
}

impl OneshotSession {
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

    fn filestore_store(
        &self,
        _file_sha256: [u8; 32],
        _part: rrg::filestore::Part,
    ) -> rrg::session::Result<rrg::filestore::Status> {
        Err(rrg::session::FilestoreUnavailableError.into())
    }

    fn filestore_path(
        &self,
        _file_sha256: [u8; 32],
    ) -> rrg::session::Result<std::path::PathBuf> {
        Err(rrg::session::FilestoreUnavailableError.into())
    }
}

fn main() {
    let args = rrg::args::from_env_args();
    rrg::log::init(&args);

    // rust-protobuf does not support Any in text or JSON formats, so we're
    // stuck taking in encoded protobufs.
    // See https://github.com/stepancheg/rust-protobuf/issues/628
    use std::io::Read as _;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)
        .expect("failed to read protobuf request");

    let message = fleetspeak::Message {
        service: String::from("GRR"),
        kind: Some(String::from("rrg.Request")),
        data,
    };

    let request = rrg::RequestUnvalidated::parse(&message)
        .expect("malformed request");
    let request = request.validate()
        .expect("invalid request");

    let mut session = OneshotSession::with_args(args);
    rrg::action::dispatch(&mut session, request).unwrap();
}
