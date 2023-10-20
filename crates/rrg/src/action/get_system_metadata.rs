// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A result of the the `get_system_metadata` action.
struct Item {
    /// The kind of the operating system the agent is running on.
    kind: ospect::os::Kind,
    /// Version string of the operating system the agent is running on.
    version: String,
    /// CPU architecture of the operating system the agent is running on.
    arch: String,
    /// Hostname of the operating system the agent is running on.
    hostname: std::ffi::OsString,
    /// FQDN of the operating system the agent is running on.
    fqdn: std::ffi::OsString,
    /// Estimated time at which the operating system was installed.
    installed: std::time::SystemTime,
}

impl Item {

    /// Returns metadata of the operating system the agent is running on.
    fn new() -> std::io::Result<Item> {
        Ok(Item {
            kind: ospect::os::kind(),
            version: ospect::os::version()?,
            arch: ospect::os::arch()?,
            hostname: ospect::os::hostname()?,
            fqdn: ospect::os::fqdn()?,
            installed: ospect::os::installed()?,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_system_metadata::Result;

    fn into_proto(self) -> rrg_proto::get_system_metadata::Result {
        use rrg_proto::into_timestamp;

        let mut proto = rrg_proto::get_system_metadata::Result::new();
        proto.set_field_type(self.kind.into());
        proto.set_version(self.version);
        proto.set_arch(self.arch);
        proto.set_hostname(self.hostname.to_string_lossy().into_owned());
        proto.set_fqdn(self.fqdn.to_string_lossy().into_owned());
        proto.set_install_time(into_timestamp(self.installed));

        proto
    }
}

// Handles invocations of the `get_system_metadata` action.
pub fn handle<S>(session: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let item = Item::new()
        .map_err(crate::session::Error::action)?;

    session.reply(item)?;

    Ok(())
}
