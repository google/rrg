// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO(panhania): Add support for binary paths in the `Metadata` object.

/// A type that holds metadata about the RRG agent.
pub struct Metadata {
    /// Name of the RRG agent.
    pub name: String,
    /// Description of the RRG agent.
    pub description: String,
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
            description: String::from(env!("CARGO_PKG_DESCRIPTION")),
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

    /// Returns a numeric representation of version metadata.
    ///
    /// This function assumes that all version components are smaller than 10.
    /// In other cases, the output is undefined (but the function call itself
    /// does not panic).
    ///
    /// # Examples
    ///
    /// ```
    /// use rrg::metadata::Version;
    ///
    /// let version = Version {
    ///     major: 1,
    ///     minor: 2,
    ///     patch: 3,
    ///     revision: 4,
    /// };
    ///
    /// assert_eq!(version.as_numeric(), 1234)
    /// ```
    pub fn as_numeric(&self) -> u32 {
        let mut result = 0;
        result = 10 * result + self.major as u32;
        result = 10 * result + self.minor as u32;
        result = 10 * result + self.patch as u32;
        result = 10 * result + self.revision as u32;
        result
    }
}

impl Into<rrg_proto::jobs::ClientInformation> for Metadata {

    fn into(self) -> rrg_proto::jobs::ClientInformation {
        let mut proto = rrg_proto::jobs::ClientInformation::new();
        proto.set_client_name(self.name);
        proto.set_client_version(self.version.as_numeric());
        proto.set_client_description(self.description);

        proto
    }
}
