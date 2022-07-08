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
//! created (using the [`from_args`] function). Then this instance should be
//! shared through the entire lifetime of a program and explicitly passed to
//! functions that care about it.
//!
//! [`from_args`]: fn.from_args.html

use std::time::Duration;

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "RRG", about = "A GRR agent rewritten in Rust.")]
pub struct Opts {
    /// A frequency of heartbeat messages to send to the Fleetspeak client.
    #[structopt(long="heartbeat-rate", name="DURATION", default_value="5s",
                parse(try_from_str = humantime::parse_duration),
                help="Specifies the frequency of heartbeat messages")]
    pub heartbeat_rate: Duration,

    /// A verbosity of logging.
    #[structopt(long="verbosity", name="LEVEL", default_value="INFO",
                help="Specifies the level of log verbosity")]
    pub verbosity: log::LevelFilter,
}

/// Parses command-line arguments.
///
/// This is a just a convenience function intended to be used as a shortcut for
/// creating instances of [`Opts`]. Ideally, it should be called only once in
/// the entire lifetime of the agent.
///
/// [`Opts`]: struct.Opts.html
pub fn from_args() -> Opts {
    Opts::from_args()
}
