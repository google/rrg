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
struct DecodeHexError;

impl std::fmt::Display for DecodeHexError {
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

/// Decodes a slice of hex digits to a Vector of byte values.
fn decode_hex(hex: &str) -> Result<Vec<u8>, DecodeHexError> {

    fn hex_char_to_int(c: char) -> Result<u8, DecodeHexError> {
        match c {
            'A'..='F' => Ok(c as u8 - b'A' + 10),
            'a'..='f' => Ok(c as u8 - b'a' + 10),
            '0'..='9' => Ok(c as u8 - b'0'),
            _ => Err(DecodeHexError),
        }
    }

    // TODO(rust-lang/rust#74985): Use `array_chunks` once stabilized.
    let chars = hex.chars().collect::<Vec<char>>();
    let pairs = chars.chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return Err(DecodeHexError);
    }

    pairs
        .map(|pair| Ok(hex_char_to_int(pair[0])? << 4 | hex_char_to_int(pair[1])?))
        .collect()
}

/// Parses a ed25519 verification key from hex data given as string to a `VerifyingKey` object.
fn parse_verfication_key(key: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let bytes = decode_hex(key).map_err(|error| error.to_string())?;
    ed25519_dalek::VerifyingKey::try_from(&bytes[..]).map_err(|error| error.to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_hex_capital_letters() {
        assert_eq!(decode_hex("A28F").unwrap(), vec![10 * 16 + 2, 8 * 16 + 15])
    }

    #[test]
    fn decode_hex_lower_case_letters() {
        assert_eq!(decode_hex("a28f").unwrap(), vec![10 * 16 + 2, 8 * 16 + 15])
    }

    #[test]
    fn decode_hex_invalid_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn decode_hex_invalid_char() {
        assert!(decode_hex("xy").is_err());
    }

    #[test]
    fn decode_hex_emtpy() {
        assert_eq!(decode_hex("").unwrap(), vec![]);
    }
}
