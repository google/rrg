// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

mod action;
mod opts;
mod session;

use std::fs::File;
use std::io::Result;

use log::error;
use opts::{Opts};

use crate::session::{Action};

fn main() -> Result<()> {
    let opts = opts::from_args();
    init(&opts);

    fleetspeak::startup(env!("CARGO_PKG_VERSION"))?;

    use session::Error::*;
    match action::startup::handle(&mut session::startup(), ()) {
        Err(Action(error)) => {
            error!("failed to collect startup metadata: {}", error);
        }
        Err(Send(error)) => {
            // Fleetspeak errors are critical, better to fail hard and
            // force agent restart.
            return Err(error.into());
        }
        Err(Encode(error)) => {
            error!("failed to encode startup metadata: {}", error);
        }
        Ok(()) => (),
    }

    loop {
        let packet = fleetspeak::collect(opts.heartbeat_rate)?;
        handle(packet.data);
    }
}

fn init(opts: &Opts) {
    init_log(opts);
}

fn init_log(opts: &Opts) {
    let level = opts.log_verbosity.level();

    let mut loggers = Vec::<Box<dyn simplelog::SharedLogger>>::new();

    if let Some(std) = &opts.log_std {
        let config = Default::default();
        let logger = simplelog::TermLogger::new(level, config, std.mode())
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

fn handle(message: rrg_proto::GrrMessage) {
    let name = match message.name {
        Some(name) => name,
        None => {
            eprintln!("action request without an action name");
            return;
        },
    };

    let session_id = match message.session_id {
        Some(session_id) => session_id,
        None => {
            eprintln!("'{}' action request without a session id", name);
            return;
        },
    };

    let request_id = match message.request_id {
        Some(request_id) => request_id,
        None => {
            eprintln!("'{}' action request without a request id", name);
            return;
        },
    };

    let mut session = Action::new(session_id, request_id);
    let result = match name.as_str() {
        "SendStartupInfo" => action::startup::handle(&mut session, ()),
        _ => {
            // TODO: Report this error to the GRR server.
            eprintln!("unsupported action '{}'", name);
            Ok(())
        }
    };

    use session::Error;
    match result {
        Ok(()) => (),
        Err(Error::Action(error)) => {
            error!("failed to execute the '{}' action: {}",
                   name, error);
        }
        Err(Error::Send(error)) => {
            panic!("failed to send a response for the '{}' action: {}",
                   name, error);
        }
        Err(Error::Encode(error)) => {
            error!("failed to encode a response for the '{}' action: {}",
                   name, error);
        }
    }
}
