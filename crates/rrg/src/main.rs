// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::{error, info};

fn main() {
    let args = rrg::args::from_env_args();
    rrg::log::init(&args);

    // TODO: https://github.com/rust-lang/rust/issues/92649
    //
    // Refactor once `panic_update_hook` is stable.

    // Because Fleetspeak does not necessarily capture RRG's standard error, it
    // might be difficult to find reason behind a crash. Thus, we extend the
    // standard panic hook to also log the panic message.
    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Note that logging is an I/O operation and it itself might panic. In
        // case of the logging failure it does not end in an endless cycle (of
        // trying to log, which panics, which tries to log and so on) but it
        // triggers an abort which is fine.
        error!("thread panicked: {info}");
        panic_hook(info)
    }));

    info!("sending Fleetspeak startup information");
    fleetspeak::startup(env!("CARGO_PKG_VERSION"));

    info!("sending RRG startup information");
    rrg::Parcel::new(rrg::Sink::Startup, rrg::Startup::now())
        .send_unaccounted();

    // TODO(@panhania): Remove once no longer needed.
    if args.ping_rate > std::time::Duration::ZERO {
        std::thread::spawn(move || {
            info!("starting the pinging thread");

            for seq in 0.. {
                info!("sending a ping message (seq: {seq})");

                rrg::Parcel::new(rrg::Sink::Ping, rrg::Ping {
                    sent: std::time::SystemTime::now(),
                    seq,
                }).send_unaccounted();

                std::thread::sleep(args.ping_rate);
            }
        });
    } else {
        info!("pinging thread is disabled");
    }

    let filestore = match &args.filestore_dir {
        Some(filestore_dir) => {
            info!("initializing filestore");

            match rrg::filestore::init(filestore_dir, args.filestore_ttl) {
                Ok(filestore) => {
                    info!("initialized filestore");
                    Some(filestore)
                }
                Err(error) => {
                    // Even if we failed to initialize filestore, RRG can still
                    // operate unless filestore actions are invoked, so we just
                    // log the error and carry on.
                    //
                    // If a filestore action is invoked, the action will fail
                    // and notify the parent flow about the issue.
                    error!("failed to initialize filestore: {error}");
                    None
                }
            }
        }
        None => {
            info!("filestore disabled");
            None
        }
    };

    info!("listening for messages");
    loop {
        let request = rrg::Request::receive(args.heartbeat_rate);
        rrg::session::FleetspeakSession::dispatch(&args, filestore.as_ref(), request);
    }
}
