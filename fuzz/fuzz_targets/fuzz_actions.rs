// Copyright 2026 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rrg::{Request, action::dispatch};
use fuzz_utils::{FuzzSession, make_proto_path};
use rrg_proto::rrg::Request as RequestProto;
use arbitrary::Arbitrary;

#[derive(Debug, Clone)]
struct SafePath(String);

impl<'a> Arbitrary<'a> for SafePath {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let safe_choices = [
            "/bin", "/etc", "/tmp", "/usr/bin", "/var/log",
            "/proc/self/status", "/etc/hosts", "/bin/ls", "/var/log/wtmp",
            "invalid_path_test"
        ];

        if u.ratio(19, 20)? {
            let choice = safe_choices[u.choose_index(safe_choices.len())?];
            return Ok(SafePath(choice.to_string()));
        }

        let random_name: String = u.arbitrary()?;
        let clean_name = random_name.replace('\0', "_").replace('/', "_");
        Ok(SafePath(format!("/tmp/{}", clean_name)))
    }
}

#[derive(Debug, Arbitrary)]
enum FuzzAction {
    GetSystemMetadata,
    ListInterfaces,
    ListMounts,
    ListUtmpUsers { path: SafePath },
    GetFileMetadata { path: SafePath },
    GetFileContents { path: SafePath, offset: u64, length: u16 },
    GetFileSha256 { path: SafePath },
    GetFilesystemTimeline { path: SafePath },
    ExecuteSignedCommand { command_blob: Vec<u8>, signature: Vec<u8>},
    GetWinregValue { key: SafePath, value_name: String },
    ListWinregValues { key: SafePath },
    ListWinregKeys { key: SafePath },
    QueryWmi { query: String },
}

impl FuzzAction {
    fn into_request(self) -> RequestProto {
        let mut request = RequestProto::new();
        request.set_request_id(12345);

        match self {
            FuzzAction::GetSystemMetadata => {
                request.set_action(rrg_proto::rrg::Action::GET_SYSTEM_METADATA);
            },
            FuzzAction::ListInterfaces => {
                request.set_action(rrg_proto::rrg::Action::LIST_INTERFACES);
            },
            FuzzAction::ListMounts => {
                request.set_action(rrg_proto::rrg::Action::LIST_MOUNTS);
            },
            FuzzAction::ListUtmpUsers { path } => {
                request.set_action(rrg_proto::rrg::Action::LIST_UTMP_USERS);
                let mut args = rrg_proto::list_utmp_users::Args::new();
                args.set_path(make_proto_path(&path.0));
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::GetFileMetadata { path } => {
                request.set_action(rrg_proto::rrg::Action::GET_FILE_METADATA);
                let mut args = rrg_proto::get_file_metadata::Args::new();
                args.mut_paths().push(make_proto_path(&path.0));
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::GetFileContents { path, offset, length } => {
                request.set_action(rrg_proto::rrg::Action::GET_FILE_CONTENTS);
                let mut args = rrg_proto::get_file_contents::Args::new();
                args.mut_paths().push(make_proto_path(&path.0));
                args.set_offset(offset);
                args.set_length(length as u64);
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::GetFileSha256 { path } => {
                request.set_action(rrg_proto::rrg::Action::GET_FILE_SHA256);
                let mut args = rrg_proto::get_file_sha256::Args::new();
                args.set_path(make_proto_path(&path.0));
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::GetFilesystemTimeline { path } => {
                request.set_action(rrg_proto::rrg::Action::GET_FILESYSTEM_TIMELINE);
                let mut args = rrg_proto::get_filesystem_timeline::Args::new();
                args.set_root(make_proto_path(&path.0));
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },

            FuzzAction::ExecuteSignedCommand { command_blob, signature } => {
                request.set_action(rrg_proto::rrg::Action::EXECUTE_SIGNED_COMMAND);
                let mut args = rrg_proto::execute_signed_command::Args::new();
                args.set_command(command_blob);
                args.set_command_ed25519_signature(signature);
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },

            FuzzAction::GetWinregValue { key, value_name } => {
                request.set_action(rrg_proto::rrg::Action::GET_WINREG_VALUE);
                let mut args = rrg_proto::get_winreg_value::Args::new();
                args.set_key(key.0);
                args.set_name(value_name);
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::ListWinregValues { key } => {
                request.set_action(rrg_proto::rrg::Action::LIST_WINREG_VALUES);
                let mut args = rrg_proto::list_winreg_values::Args::new();
                args.set_key(key.0);
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::ListWinregKeys { key } => {
                request.set_action(rrg_proto::rrg::Action::LIST_WINREG_KEYS);
                let mut args = rrg_proto::list_winreg_keys::Args::new();
                args.set_key(key.0);
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
            FuzzAction::QueryWmi { query } => {
                request.set_action(rrg_proto::rrg::Action::QUERY_WMI);
                let mut args = rrg_proto::query_wmi::Args::new();
                args.set_query(query);
                request.set_args(protobuf::well_known_types::any::Any::pack(&args).unwrap());
            },
        }
        request
    }
}

fuzz_target!(|actions: Vec<FuzzAction>| {
    let mut session = FuzzSession::new();

    for action in actions {
        let proto = action.into_request();
        // Parsing Check
        let Ok(request) = Request::try_from(proto) else {
            continue;
        };
        // Logic Check
        let _ = dispatch(&mut session, request);
    }
});
