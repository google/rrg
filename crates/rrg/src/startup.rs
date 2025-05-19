// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Information about the agent startup.
pub struct Startup {
    /// Metadata about the agent that has been started.
    pub metadata: Metadata,
    // Path to the agent's executable that is running.
    pub path: Option<std::path::PathBuf>,
    /// Value of command-line arguments that the agent was invoked with.
    pub args: Vec<String>,
    /// Time at which the agent was started.
    pub agent_started: std::time::SystemTime,
    // TOOD(@panhania): Add support for the `os_booted` field.
}

impl Startup {

    /// Creates a startup information as of now.
    pub fn now() -> Startup {
        let path = std::env::current_exe().and_then(std::fs::canonicalize)
            .inspect_err(|error| {
                log::error!("failed to obtain agent's path: {error}")
            })
            .ok();

        Startup {
            metadata: Metadata::from_cargo(),
            path,
            args: std::env::args().collect(),
            agent_started: std::time::SystemTime::now(),
        }
    }
}

impl crate::response::Item for Startup {
    type Proto = rrg_proto::startup::Startup;

    fn into_proto(self) -> rrg_proto::startup::Startup {
        self.into()
    }
}

/// A type that holds metadata about the RRG agent.
pub struct Metadata {
    /// Name of the RRG agent.
    pub name: String,
    /// Version of the RRG agent.
    pub version: Version,
}

impl Metadata {

    /// Constructs metadata object from Cargo information.
    ///
    /// This function assumes that are relevant crate information is correctly
    /// specified in the `Cargo.toml` file.
    pub fn from_cargo() -> Metadata {
        Metadata {
            name: String::from(env!("CARGO_PKG_NAME")),
            version: Version::from_cargo(),
        }
    }
}

/// A type for representing version metadata.
pub struct Version {
    /// Major version of the RRG agent (`x` in `x.y.z`).
    pub major: u8,
    /// Minor version of the RRG agent (`y` in `x.y.z`).
    pub minor: u8,
    /// Patch version of the RRG agent (`z` in `x.y.z`).
    pub patch: u8,
    /// Pre-release label of the RRG agent (`foo` in `x.y.z-foo`).
    pub pre: &'static str,
}

impl Version {

    /// Constructs version metadata from Cargo information.
    ///
    /// This function assumes that are relevant crate information is correctly
    /// specified in the `Cargo.toml` file.
    pub fn from_cargo() -> Version {
        Version {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
            patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
            pre: env!("CARGO_PKG_VERSION_PRE"),
        }
    }
}

impl Into<rrg_proto::startup::Startup> for Startup {

    fn into(self) -> rrg_proto::startup::Startup {
        use rrg_proto::into_timestamp;

        let mut proto = rrg_proto::startup::Startup::new();
        proto.set_metadata(self.metadata.into());
        if let Some(path) = self.path {
            proto.set_path(path.into());
        }
        proto.set_args(self.args.into());
        proto.set_agent_startup_time(into_timestamp(self.agent_started));

        proto
    }
}

impl Into<rrg_proto::startup::Metadata> for Metadata {

    fn into(self) -> rrg_proto::startup::Metadata {
        let mut proto = rrg_proto::startup::Metadata::new();
        proto.set_name(self.name);
        // TODO(@panhania): Add support for remaining fields.
        proto.set_version(self.version.into());

        proto
    }
}

impl Into<rrg_proto::startup::Version> for Version {

    fn into(self) -> rrg_proto::startup::Version {
        let mut proto = rrg_proto::startup::Version::new();
        proto.set_major(u32::from(self.major));
        proto.set_minor(u32::from(self.minor));
        proto.set_patch(u32::from(self.patch));
        proto.set_pre(String::from(self.pre));

        proto
    }
}
