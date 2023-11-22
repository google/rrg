// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use log::error;

/// A result of the the `get_system_metadata` action.
struct Item {
    /// The kind of the operating system the agent is running on.
    kind: ospect::os::Kind,
    /// Version string of the operating system the agent is running on.
    version: Option<String>,
    /// CPU architecture of the operating system the agent is running on.
    arch: Option<String>,
    /// Hostname of the operating system the agent is running on.
    hostname: Option<std::ffi::OsString>,
    /// FQDN of the operating system the agent is running on.
    fqdn: Option<std::ffi::OsString>,
    /// Estimated time at which the operating system was installed.
    installed: Option<std::time::SystemTime>,
}

impl Item {

    /// Returns metadata of the operating system the agent is running on.
    fn new() -> std::io::Result<Item> {
        let version = match ospect::os::version() {
            Ok(version) => Some(version),
            Err(error) => {
                error!("failed to collect system version: {error}");
                None
            }
        };
        let arch = match ospect::os::arch() {
            Ok(arch) => Some(arch),
            Err(error) => {
                error!("failed to collect system architecture: {error}");
                None
            }
        };
        let hostname = match ospect::os::hostname() {
            Ok(hostname) => Some(hostname),
            Err(error) => {
                error!("failed to collect system hostname: {error}");
                None
            }
        };
        let fqdn = match ospect::os::fqdn() {
            Ok(fqdn) => Some(fqdn),
            Err(error) => {
                error!("failed to collect system FQDN: {error}");
                None
            }
        };
        let installed = match ospect::os::installed() {
            Ok(installed) => Some(installed),
            Err(error) => {
                error!("failed to collect system installation time: {error}");
                None
            }
        };

        Ok(Item {
            kind: ospect::os::kind(),
            version,
            arch,
            hostname,
            fqdn,
            installed,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::get_system_metadata::Result;

    fn into_proto(self) -> rrg_proto::get_system_metadata::Result {
        use rrg_proto::into_timestamp;

        let mut proto = rrg_proto::get_system_metadata::Result::new();
        proto.set_field_type(self.kind.into());
        if let Some(version) = self.version {
            proto.set_version(version);
        }
        if let Some(arch) = self.arch {
            proto.set_arch(arch);
        }
        if let Some(hostname) = self.hostname {
            proto.set_hostname(hostname.to_string_lossy().into_owned());
        }
        if let Some(fqdn) = self.fqdn {
            proto.set_fqdn(fqdn.to_string_lossy().into_owned());
        }
        if let Some(installed) = self.installed {
            proto.set_install_time(into_timestamp(installed));
        }

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
