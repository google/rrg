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
        Err(Parse(error)) => {
            error!("malformed action input: {}", error);
        }
        Ok(()) => (),
    }

    loop {
        use fleetspeak::ReadError::*;
        let packet = match fleetspeak::collect(opts.heartbeat_rate) {
            Ok(packet) => packet,
            Err(Malformed(error)) => {
                error!("received a malformed message: {}", error);
                continue;
            }
            Err(Decode(error)) => {
                error!("failed to decode the message: {}", error);
                continue;
            }
            Err(error) => return Err(error.into()),
        };

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
    let name = match &message.name {
        Some(name) => name.clone(),
        None => {
            error!("unspecified action to execute");
            return;
        }
    };

    let result = match name.as_str() {
        "SendStartupInfo" => session::handle(action::startup::handle, message),
        _ => {
            error!("unsupported action: {}", name);
            return;
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
        Err(Error::Parse(error)) => {
            error!("malformed input for the '{}' action: {}",
                   name, error);
        }
    }
}
