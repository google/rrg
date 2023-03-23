// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Metadata associated with the operating system.
struct Metadata {
    /// The kind of the operating system the agent is running on.
    kind: ospect::os::Kind,
    /// Version string of the operating system the agent is running on.
    version: String,
    /// Estimated time at which the operating system was installed.
    installed: std::time::SystemTime,
}

impl Metadata {

    fn new() -> std::io::Result<Metadata> {
        Ok(Metadata {
            kind: ospect::os::kind(),
            version: ospect::os::version()?,
            installed: ospect::os::installed()?,
        })
    }
}

impl From<Metadata> for rrg_proto::v2::os::Metadata {

    fn from(metadata: Metadata) -> rrg_proto::v2::os::Metadata {
        // TODO(panhania@): Upgrade to version 3.2.0 of `protobuf` that supports
        // `From<SystemTime>` conversion of Protocol Buffers `Timestamp`.
        let mut proto = rrg_proto::v2::os::Metadata::new();
        proto.set_field_type(metadata.kind.into());
        proto.set_version(metadata.version);

        // TODO(panhania@): Upgrade to version 3.2.0 of `protobuf` that supports
        // `From<SystemTime>` conversion of Protocol Buffers `Timestamp`.
        let installed_since_epoch = metadata.installed
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();

        let mut install_time = protobuf::well_known_types::Timestamp::new();
        install_time
            .set_nanos(installed_since_epoch.subsec_nanos() as i32);
        install_time
            .set_seconds(installed_since_epoch.as_secs() as i64);
        proto.set_install_time(install_time);

        proto
    }
}

/// A result of the the `get_system_metadata` action.
struct Item {
    /// Metadata associated with the operating system the agent is running on.
    metadata: Metadata,
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::v2::get_system_metadata::Result;

    fn into_proto(self) -> rrg_proto::v2::get_system_metadata::Result {
        let mut proto = rrg_proto::v2::get_system_metadata::Result::new();
        proto.set_metadata(self.metadata.into());

        proto
    }
}

// Handles invocations of the `get_system_metadata` action.
pub fn handle<S>(session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let metadata = Metadata::new()
        .map_err(crate::session::Error::action)?;

    session.reply(Item {
        metadata,
    })?;

    Ok(())
}
