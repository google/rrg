// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_utils::FuzzSession;
use rrg::action::execute_signed_command;
use rrg_proto::rrg::Request as RequestProto;
use rrg::Request;
use arbitrary::Arbitrary;
use protobuf::Message;


#[derive(Debug, Arbitrary)]
struct FuzzCommandArg {
    is_signed: bool,
    signed: String,
    unsigned_allowed: bool,
}

#[derive(Debug, Arbitrary)]
struct FuzzCommand {
    path: String,
    args: Vec<FuzzCommandArg>,
    env: Vec<(String, String)>,

    use_signed_stdin: bool,
    signed_stdin: Vec<u8>,
    unsigned_stdin_allowed: bool,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    // The structured command we will serialize
    command: FuzzCommand,

    signature: Vec<u8>,
    unsigned_stdin: Vec<u8>,
    unsigned_args: Vec<String>,
    unsigned_env: Vec<(String, String)>,
}

fuzz_target!(|input: FuzzInput| {
    let mut session = FuzzSession::new();

    //Construct the Inner 'Command' Proto ---
    let mut cmd_proto = rrg_proto::execute_signed_command::Command::new();

    let mut path_proto = rrg_proto::fs::Path::new();
    path_proto.set_raw_bytes(input.command.path.into_bytes());
    cmd_proto.set_path(path_proto);

    for f_arg in input.command.args {
        let mut arg_proto = rrg_proto::execute_signed_command::command::Arg::new();
        if f_arg.is_signed {
            arg_proto.set_signed(f_arg.signed);
        } else {
            arg_proto.set_unsigned_allowed(f_arg.unsigned_allowed);
        }
        cmd_proto.mut_args().push(arg_proto);
    }

    for (k, v) in input.command.env {
        cmd_proto.mut_env_signed().insert(k, v);
    }

    if input.command.use_signed_stdin {
        cmd_proto.set_signed_stdin(input.command.signed_stdin);
    } else {
        cmd_proto.set_unsigned_stdin_allowed(input.command.unsigned_stdin_allowed);
    }

    // Serialize the inner command to bytes
    let command_bytes = cmd_proto.write_to_bytes().unwrap_or_default();

    // Construct the Outer Action Args ---
    let mut args = rrg_proto::execute_signed_command::Args::new();
    args.set_command(command_bytes);
    args.set_command_ed25519_signature(input.signature);
    args.set_unsigned_stdin(input.unsigned_stdin);
    for u_arg in input.unsigned_args {
        args.mut_unsigned_args().push(u_arg);
    }
    for (k, v) in input.unsigned_env {
        args.mut_unsigned_env().insert(k, v);
    }

    let mut proto = RequestProto::new();
    proto.set_request_id(12345);
    proto.set_action(rrg_proto::rrg::Action::EXECUTE_SIGNED_COMMAND);
    proto.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());

    if let Ok(request) = Request::try_from(proto) {
        if let Ok(internal_args) = request.args() {
            // Fuzzing Goal:
            // 1. Deserialization of 'command_bytes' inside RRG.
            // 2. Logic checking 'unsigned_args' against the 'Command' policy.
            // 3. Signature verification (will fail, but code path is exercised).
            let _ = execute_signed_command::handle(&mut session, internal_args);
        }
    }
});
