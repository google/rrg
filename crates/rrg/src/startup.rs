// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO(panhania): Add support for binary paths in the `Metadata` object.

/// Sends a system message with startup information to the GRR server.
pub fn startup() -> Result<(), fleetspeak::WriteError> {
    let startup = Startup::now();

    crate::Parcel {
        sink: crate::Sink::Blob,
        payload: startup,
    }.send_unaccounted()
}

/// Information about the agent startup.
pub struct Startup {
    /// Metadata about the agent that has been started.
    pub metadata: Metadata,
    /// Value of command-line arguments that the agent was invoked with.
    pub args: Vec<String>,
    /// Time at which the agent was started.
    pub agent_started: std::time::SystemTime,
    // TOOD(@panhania): Add support for the `os_booted` field.
}

impl Startup {

    /// Creates a startup information as of now.
    pub fn now() -> Startup {
        Startup {
            metadata: Metadata::from_cargo(),
            args: std::env::args().collect(),
            agent_started: std::time::SystemTime::now(),
        }
    }
}

impl crate::Output for Startup {
    type Proto = rrg_proto::v2::startup::Startup;

    fn into_proto(self) -> rrg_proto::v2::startup::Startup {
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
    /// Major version of the RRG agent (`x` in `x.y.z.r`).
    pub major: u8,
    /// Minor version of the RRG agent (`y` in `x.y.z.r`).
    pub minor: u8,
    /// Patch version of the RRG agent (`z` in `x.y.z.r`).
    pub patch: u8,
    /// Revision version of the RRG agent (`r` in `x.y.z.r`).
    pub revision: u8,
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
            revision: env!("CARGO_PKG_VERSION_PRE").parse().unwrap_or(0),
        }
    }
}

impl Into<rrg_proto::v2::startup::Startup> for Startup {

    fn into(self) -> rrg_proto::v2::startup::Startup {
        let mut proto = rrg_proto::v2::startup::Startup::new();
        proto.set_metadata(self.metadata.into());
        proto.set_args(self.args.into());

        // TODO(panhania@): Upgrade to version 3.2.0 of `protobuf` that supports
        // `From<SystemTime>` conversion of Protocol Buffers `Timestamp`.
        let agent_started_since_epoch = self.agent_started
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();

        let mut agent_startup_time = protobuf::well_known_types::Timestamp::new();
        agent_startup_time
            .set_nanos(agent_started_since_epoch.subsec_nanos() as i32);
        agent_startup_time
            .set_seconds(agent_started_since_epoch.as_secs() as i64);
        proto.set_agent_startup_time(agent_startup_time);

        proto
    }
}

impl Into<rrg_proto::v2::startup::Metadata> for Metadata {

    fn into(self) -> rrg_proto::v2::startup::Metadata {
        let mut proto = rrg_proto::v2::startup::Metadata::new();
        proto.set_name(self.name);
        // TODO(@panhania): Add support for remaining fields.
        proto.set_version(self.version.into());

        proto
    }
}

impl Into<rrg_proto::v2::startup::Version> for Version {

    fn into(self) -> rrg_proto::v2::startup::Version {
        let mut proto = rrg_proto::v2::startup::Version::new();
        proto.set_major(u32::from(self.major));
        proto.set_minor(u32::from(self.minor));
        proto.set_patch(u32::from(self.patch));
        proto.set_revision(u32::from(self.revision));

        proto
    }
}
