// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Handlers and types for agent's actions.
//!
//! The basic functionality that a GRR agent exposes is called an _action_.
//! Actions are invoked by the server (when running a _flow_), should gather
//! requested information and report back to the server.
//!
//! In RRG each action consists of three components: a request type, a response
//! type and an action handler. Request and response types wrap lower-level
//! Protocol Buffer messages sent by and to the GRR server. Handlers accept one
//! instance of the corresponding request type and send some (zero or more)
//! instances of the corresponding response type.

#[cfg(feature = "action-get_system_metadata")]
pub mod get_system_metadata;

#[cfg(feature = "action-get_file_metadata")]
pub mod get_file_metadata;

#[cfg(feature = "action-get_file_metadata_kmx")]
pub mod get_file_metadata_kmx;

#[cfg(feature = "action-get_file_contents")]
pub mod get_file_contents;

#[cfg(feature = "action-get_file_contents_kmx")]
pub mod get_file_contents_kmx;

#[cfg(feature = "action-get_file_sha256")]
pub mod get_file_sha256;

#[cfg(feature = "action-grep_file_contents")]
pub mod grep_file_contents;

#[cfg(feature = "action-get_filesystem_timeline")]
pub mod get_filesystem_timeline;

#[cfg(feature = "action-get_filesystem_timeline_tsk")]
pub mod get_filesystem_timeline_tsk;

#[cfg(feature = "action-get_tcp_response")]
pub mod get_tcp_response;

#[cfg(feature = "action-list_connections")]
pub mod list_connections;

#[cfg(feature = "action-list_interfaces")]
pub mod list_interfaces;

#[cfg(feature = "action-list_mounts")]
pub mod list_mounts;

#[cfg(feature = "action-list_utmp_users")]
pub mod list_utmp_users;

#[cfg(feature = "action-get_winreg_value")]
pub mod get_winreg_value;

#[cfg(feature = "action-list_winreg_values")]
pub mod list_winreg_values;

#[cfg(feature = "action-list_winreg_keys")]
pub mod list_winreg_keys;

#[cfg(feature = "action-query_wmi")]
pub mod query_wmi;

#[cfg(feature = "action-execute_signed_command")]
pub mod execute_signed_command;

#[cfg(feature = "action-dump_process_memory")]
pub mod dump_process_memory;

#[cfg(feature = "action-scan_memory_yara")]
pub mod scan_memory_yara;

use log::info;

/// Dispatches the given `request` to an appropriate action handler.
///
/// This method is a mapping between action names (as specified in the protocol)
/// and action handlers (implemented on the agent).
///
/// # Errors
///
/// This function will return an error if the given action is unknown (or not
/// yet implemented).
///
/// It will also error out if the action execution itself fails for whatever
/// reason.
pub fn dispatch<'s, S>(session: &mut S, request: crate::Request) -> Result<(), crate::session::Error>
where
    S: crate::session::Session,
{
    use crate::request::Action::*;

    let request_id = request.id();
    let action = request.action();

    info!("dispatching request '{request_id}': {action}");

    let result = match request.action() {
        #[cfg(feature = "action-get_system_metadata")]
        GetSystemMetadata => {
            handle(session, request, self::get_system_metadata::handle)
        }
        #[cfg(feature = "action-get_file_metadata")]
        GetFileMetadata => {
            handle(session, request, self::get_file_metadata::handle)
        }
        #[cfg(feature = "action-get_file_metadata_kmx")]
        GetFileMetadataKmx => {
            handle(session, request, self::get_file_metadata_kmx::handle)
        }
        #[cfg(feature = "action-get_file_contents")]
        GetFileContents => {
            handle(session, request, self::get_file_contents::handle)
        }
        #[cfg(feature = "action-get_file_contents_kmx")]
        GetFileContentsKmx => {
            handle(session, request, self::get_file_contents_kmx::handle)
        }
        #[cfg(feature = "action-get_file_sha256")]
        GetFileSha256 => {
            handle(session, request, self::get_file_sha256::handle)
        }
        #[cfg(feature = "action-grep_file_contents")]
        GrepFileContents => {
            handle(session, request, self::grep_file_contents::handle)
        }
        #[cfg(feature = "action-get_filesystem_timeline")]
        GetFilesystemTimeline => {
            handle(session, request, self::get_filesystem_timeline::handle)
        }
        #[cfg(feature = "action-get_filesystem_timeline_tsk")]
        GetFilesystemTimelineTsk => {
            handle(session, request, self::get_filesystem_timeline_tsk::handle)
        }
        #[cfg(feature = "action-get_tcp_response")]
        GetTcpResponse => {
            handle(session, request, self::get_tcp_response::handle)
        }
        #[cfg(feature = "action-list_connections")]
        ListConnections => {
            handle(session, request, self::list_connections::handle)
        }
        #[cfg(feature = "action-list_interfaces")]
        ListInterfaces => {
            handle(session, request, self::list_interfaces::handle)
        }
        #[cfg(feature = "action-list_mounts")]
        ListMounts => {
            handle(session, request, self::list_mounts::handle)
        }
        #[cfg(feature = "action-list_utmp_users")]
        ListUtmpUsers => {
            handle(session, request, self::list_utmp_users::handle)
        }
        #[cfg(feature = "action-get_winreg_value")]
        GetWinregValue => {
            handle(session, request, self::get_winreg_value::handle)
        }
        #[cfg(feature = "action-list_winreg_values")]
        ListWinregValues => {
            handle(session, request, self::list_winreg_values::handle)
        }
        #[cfg(feature = "action-list_winreg_keys")]
        ListWinregKeys => {
            handle(session, request, self::list_winreg_keys::handle)
        }
        #[cfg(feature = "action-query_wmi")]
        QueryWmi => {
            handle(session, request, self::query_wmi::handle)
        }
        #[cfg(feature = "action-execute_signed_command")]
        ExecuteSignedCommand => {
            handle(session, request, self::execute_signed_command::handle)
        }
        #[cfg(feature = "action-dump_process_memory")]
        DumpProcessMemory => {
            handle(session, request, self::dump_process_memory::handle)
        }
        #[cfg(feature = "action-scan_memory_yara")]
        ScanProcessMemoryYara => {
            handle(session, request, self::scan_memory_yara::handle)
        }
        // We allow `unreachable_patterns` because otherwise we get a warning if
        // we compile with all the actions enabled.
        #[allow(unreachable_patterns)]
        action => {
            return Err(crate::session::Error::unsupported_action(action));
        }
    };

    info!("finished dispatching request '{request_id}'");

    result
}

/// Handles a `request` using the specified `handler`.
///
/// This method will attempt to interpret request arguments for the specific
/// action and execute the handler with them.
///
/// # Errors
///
/// This function will return an error if the request arguments cannot be parsed
/// for the specific action or if the action execution fails.
fn handle<S, A, H>(session: &mut S, request: crate::Request, handler: H) -> crate::session::Result<()>
where
    S: crate::session::Session,
    A: crate::request::Args,
    H: FnOnce(&mut S, A) -> crate::session::Result<()>,
{
    Ok(handler(session, request.args()?)?)
}
