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
