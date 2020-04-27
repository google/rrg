// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::fs::File;

use log::{error, info};

use rrg::action;
use rrg::session;
use rrg::opts::{self, Opts};

fn main() {
    let opts = opts::from_args();
    init(&opts);

    fleetspeak::startup(env!("CARGO_PKG_VERSION"))
        .expect("failed to initialize Fleetspeak connection");

    match action::startup::handle(&mut session::Adhoc, ()) {
        Err(error) => {
            error!("failed to collect startup information: {}", error);
        }
        Ok(()) => {
            info!("successfully sent startup information");
        }
    }

    rrg::listen(&opts);
}

fn init(opts: &Opts) {
    init_log(opts);
}

fn init_log(opts: &Opts) {
    let level = opts.log_verbosity.level();

    let mut loggers = Vec::<Box<dyn simplelog::SharedLogger>>::new();

    if let Some(stream) = &opts.log_stream {
        let config = Default::default();
        let logger = simplelog::TermLogger::new(level, config, stream.mode())
            .expect("failed to create a terminal logger");

        loggers.push(logger);
    }

    if let Some(path) = &opts.log_file {
        let file = File::create(path)
            .expect("failed to create the log file");

        let config = Default::default();
        let logger = simplelog::WriteLogger::new(level, config, file);

        loggers.push(logger);
    }

    simplelog::CombinedLogger::init(loggers)
        .expect("failed to init logging");
}
