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
                help="Specifies the level of log verbosity")]
    pub log_verbosity: Verbosity,

    #[structopt(long="log-std", name="STD",
                help="Enables logging to the specified standard stream")]
    pub log_std: Option<Std>,

    #[structopt(long="log-file", name="FILE",
                help="Enables logging to the specified file")]
    pub log_file: Option<PathBuf>,

    #[structopt(long="heartbeat-rate", name="DURATION", default_value="5s",
                parse(try_from_str = humantime::parse_duration),
                help="Specifies the frequency of heartbeat messages")]
    pub heartbeat_rate: Duration,
}

pub fn from_args() -> Opts {
    Opts::from_args()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verbosity {
    level: log::LevelFilter,
}

impl Verbosity {

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Std {
    Out,
    Err,
    Mix,
}

impl Std {

    pub fn mode(&self) -> simplelog::TerminalMode {
        use simplelog::TerminalMode::*;

        match self {
            Std::Out => Stdout,
            Std::Err => Stderr,
            Std::Mix => Mixed,
        }
    }
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
