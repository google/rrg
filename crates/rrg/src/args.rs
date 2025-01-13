// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Structured specification of command-line arguments.
//!
//! This module specifies all command-line arguments that RRG offers and exposes
//! functions for parsing them into a high-level structure.
//!
//! Ideally, only one instance of this high-level structure should ever be
//! created (using the [`from_env_args`] function). Then this instance should be
//! shared through the entire lifetime of a program and explicitly passed to
//! functions that care about it.
//!
//! [`from_env_args`]: fn.from_env_args.html

use std::time::Duration;

#[derive(argh::FromArgs)]
/// A GRR agent written in Rust.
pub struct Args {
    /// A frequency of heartbeat messages to send to the Fleetspeak client.
    #[argh(option,
           long="heartbeat-rate",
           arg_name="DURATION",
           default="::std::time::Duration::from_secs(5)",
           description="frequency of heartbeat messages sent to Fleetspeak",
           from_str_fn(parse_duration))]
    pub heartbeat_rate: Duration,

    /// A verbosity of logging.
    #[argh(option,
           long="verbosity",
           arg_name="LEVEL",
           description="level of logging verbosity",
           default="::log::LevelFilter::Info")]
    pub verbosity: log::LevelFilter,

    /// Determines whether to log to the standard output.
    #[argh(switch,
           long="log-to-stdout",
           description="whether to log to standard output")]
    pub log_to_stdout: bool,

    /// Determines whether to log to a file (and where).
    #[argh(option,
           long="log-to-file",
           arg_name="PATH",
           description="whether to log to a file")]
    pub log_to_file: Option<std::path::PathBuf>,

    /// The public key for verfying signed commands.
    #[argh(option,
       long="command-verification-key",
       arg_name="KEY",
       description="verification key for signed commands",
       from_str_fn(parse_verfication_key))]
    pub command_verification_key: Option<ed25519_dalek::VerifyingKey>,
}

#[derive(Debug)]
struct HexDecodeError();

impl std::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hex decoding failed")
    }
}


/// Parses command-line arguments.
///
/// This is a just a convenience function intended to be used as a shortcut for
/// creating instances of [`Args`]. Ideally, it should be called only once in
/// the entire lifetime of the agent.
///
/// [`Args`]: struct.Args.html
pub fn from_env_args() -> Args {
    argh::from_env()
}

/// Parses a human-friendly duration description to a `Duration` object.
fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|error| error.to_string())
}

/// Decodes a Vector of hex digits to a Vector of byte values.
fn hex_decode(hex: Vec<u8>) -> Result<Vec<u8>, HexDecodeError> {
    if hex.len() % 2 != 0 {
        return Err(HexDecodeError());
    }

    fn hex_char_to_int(c: u8) -> Result<u8, HexDecodeError> {
        match c {
            b'A'..=b'F' => Ok(c - b'A' + 10),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'0'..=b'9' => Ok(c - b'0'),
            _ => Err(HexDecodeError()),
        }
    }

    hex.chunks(2)
        .into_iter()
        .map(|pair| Ok(hex_char_to_int(pair[0])? << 4 | hex_char_to_int(pair[1])?))
        .collect()
}

/// Parses a ed25519 verification key from hex data given as string to a `VerifyingKey` object.
fn parse_verfication_key(key: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let bytes = hex_decode(key.as_bytes().to_vec()).map_err(|error| error.to_string())?;
    ed25519_dalek::VerifyingKey::try_from(&bytes[..]).map_err(|error| error.to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hex_decode() {
        let hex = vec![b'a', b'2', b'8', b'F'];
        assert_eq!(hex_decode(hex).unwrap(), vec![10 * 16 + 2, 8 * 16 + 15])
    }

    #[test]
    fn test_invalid_length() {
        let hex = vec![b'a', b'b', b'c'];
        assert!(hex_decode(hex).is_err());
    }

    #[test]
    fn test_invalid_char() {
        let hex = vec![b'x', b'y'];
        assert!(hex_decode(hex).is_err());
    }

    #[test]
    pub fn test_empty() {
        let empty: Vec<u8> = vec![];
        assert_eq!(hex_decode(empty).unwrap(), vec![]);
    }
}
