// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::time::Duration;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "RRG", about = "A GRR agent rewritten in Rust.")]
pub struct Opts {
    #[structopt(long="log-verbosity", name="LEVEL", default_value="info",
                help="A log verbosity level")]
    pub log_verbosity: Verbosity,

    #[structopt(long="log-std", name="STD",
                help="A standard stream to log to")]
    pub log_std: Option<Std>,

    #[structopt(long="log-file", name="FILE",
                help="A file to log to")]
    pub log_file: Option<PathBuf>,

    #[structopt(long="heartbeat-rate", name="DURATION", default_value="5s",
                parse(try_from_str = humantime::parse_duration),
                help="A frequency of Fleetspeak heartbeat messages.")]
    pub heartbeat_rate: Duration,
}

pub fn from_args() -> Opts {
    Opts::from_args()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verbosity(pub log::LevelFilter);

impl std::str::FromStr for Verbosity {

    type Err = String; // TODO.

    fn from_str(string: &str) -> std::result::Result<Verbosity, String> {
        use log::LevelFilter::*;

        match string {
            "quiet" => Ok(Verbosity(Off)),
            "error" => Ok(Verbosity(Error)),
            "warn" => Ok(Verbosity(Warn)),
            "info" => Ok(Verbosity(Info)),
            "debug" => Ok(Verbosity(Debug)),
            "trace" => Ok(Verbosity(Trace)),
            _ => Err(format!("invalid verbosity choice '{}'", string)),
        }
    }
}

// TODO: This should just be a wrapper around `simplelog::TerminalMode`, but
// it does not implement standard traits. So, for now, we just re-implement it
// like that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Std {
    Out,
    Err,
    Mix,
}

impl std::str::FromStr for Std {

    type Err = String; // TODO.

    fn from_str(string: &str) -> std::result::Result<Std, String> {
        match string {
            "out" => Ok(Std::Out),
            "err" => Ok(Std::Err),
            "mix" => Ok(Std::Mix),
            _ => Err(format!("invalid std choice '{}'", string)),
        }
    }
}
