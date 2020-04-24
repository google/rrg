// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// A type that holds metadata about the RRG agent.
pub struct Metadata {
    /// Name of the RRG agent.
    pub name: String,
    /// Description of the RRG agent.
    pub description: String,
    /// Version of the RRG agent.
    pub version: Version,
}

/// A type for representing version metadata.
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
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
    /// use rrg::action::startup::Version;
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
