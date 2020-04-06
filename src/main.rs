// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

mod opts;

use std::fs::File;
use std::io::Result;

use opts::{Opts, Std};

fn main() -> Result<()> {
    let opts = opts::from_args();
    init(&opts);

    fleetspeak::startup(env!("CARGO_PKG_VERSION"))?;

    loop {
        let packet = fleetspeak::collect(opts.heartbeat_rate)?;
        handle(packet.data);
    }
}

fn init(opts: &Opts) {
    let level = opts.log_verbosity.level();
    let mut loggers = Vec::<Box<dyn simplelog::SharedLogger>>::new();

    if let Some(std) = &opts.log_std {
        let config = Default::default();

        use simplelog::TerminalMode::*;
        let logger = simplelog::TermLogger::new(level, config, match std {
            Std::Out => Stdout,
            Std::Err => Stderr,
            Std::Mix => Mixed,
        }).expect("failed to create a terminal logger");

        loggers.push(logger);
    }

    if let Some(path) = &opts.log_file {
        let config = Default::default();

        let file = File::create(path).expect("failed to create the log file");
        let logger = simplelog::WriteLogger::new(level, config, file);

        loggers.push(logger);
    }

    simplelog::CombinedLogger::init(loggers).expect("failed to init logging");
}

fn handle(message: rrg_proto::GrrMessage) {
    match message.name {
        Some(name) => println!("requested to execute the '{}' action", name),
        None => eprintln!("missing action name to execute"),
    }
}
