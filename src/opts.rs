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
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "RRG", about = "A GRR agent rewritten in Rust.")]
pub struct Opts {
    /// A level of log verbosity.
    #[structopt(long="log-verbosity", name="LEVEL", default_value="info",
                help="Specifies the level of log verbosity")]
    pub log_verbosity: Verbosity,

    /// A standard stream to log into.
    #[structopt(long="log-std", name="STD",
                help="Enables logging to the specified standard stream")]
    pub log_std: Option<Std>,

    /// A path to the file to log into.
    #[structopt(long="log-file", name="FILE",
                help="Enables logging to the specified file")]
    pub log_file: Option<PathBuf>,

    /// A frequence of heartbeat messages to send to the Fleetspeak client.
    #[structopt(long="heartbeat-rate", name="DURATION", default_value="5s",
                parse(try_from_str = humantime::parse_duration),
                help="Specifies the frequency of heartbeat messages")]
    pub heartbeat_rate: Duration,
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

/// A type representing level of log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verbosity {
    level: log::LevelFilter,
}

impl Verbosity {

    /// Yields a corresponding log filter.
    pub fn level(&self) -> log::LevelFilter {
        self.level
    }
}

impl std::str::FromStr for Verbosity {

    type Err = String; // TODO.

    fn from_str(string: &str) -> std::result::Result<Verbosity, String> {
        use log::LevelFilter::*;

        let level = match string {
            "quiet" => Off,
            "error" => Error,
            "warn" => Warn,
            "info" => Info,
            "debug" => Debug,
            "trace" => Trace,
            _ => return Err(format!("invalid verbosity choice '{}'", string)),
        };

        Ok(Verbosity {
            level: level,
        })
    }
}

// TODO: This should just be a wrapper around `simplelog::TerminalMode`, but
// it does not implement standard traits. So, for now, we just re-implement it
// like that.
/// A type listing different options for logging to standard streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Std {
    mode: simplelog::TerminalMode,
}

impl Std {

    /// Yields a corresponding terminal mode.
    pub fn mode(&self) -> simplelog::TerminalMode {
        self.mode
    }
}

impl std::str::FromStr for Std {

    type Err = String; // TODO.

    fn from_str(string: &str) -> std::result::Result<Std, String> {
        use simplelog::TerminalMode::*;

        let mode = match string {
            "out" => Stdout,
            "err" => Stderr,
            "mix" => Mixed,
            _ => return Err(format!("invalid std choice '{}'", string)),
        };

        Ok(Std {
            mode: mode,
        })
    }
}
