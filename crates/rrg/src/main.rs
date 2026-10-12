// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::{error, info, warn};

fn main() {
    // We need to be able to obtain static reference to the `Comms` object to be
    // able to use it with the response logger which is a global object and can
    // not hold references to temporary objects. Thus, we wrap it in `OnceLock`.
    static COMMS: std::sync::OnceLock<fleetspeak::Comms> = std::sync::OnceLock::new();
    let comms = COMMS.get_or_init(|| {
        // SAFETY: We are calling `from_env` at the very beginning of the `main`
        // function and so we can guarantee that environment variables have not
        // been tampered with and so the Fleetspeak file descriptors are what
        // the parent process set.
        //
        // It is also the only place where we invoke this function.
        unsafe {
            fleetspeak::Comms::from_env()
        }.expect("failed to initialize Fleetspeak")
    });

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
    // TODO(https://github.com/rust-lang/rust/issues/61695): Make more readable
    // once `unwrap_infallible` is stable.
    match comms.startup(env!("CARGO_PKG_VERSION")) {
        Ok(()) => (),
        Err(error) => panic!("failed to notify Fleetspeak about startup: {error}"),
    }

    info!("sending RRG startup information");
    rrg::Parcel::new(rrg::Sink::Startup, rrg::Startup::now())
        .send_unaccounted(comms);

    if let Some(request_file_path) = &args.request_file {
        match rrg::abort::open_request_file(request_file_path) {
            Ok(request_file) => {
                info! {
                    "request file at '{}' found, sending RRG abort information",
                    request_file_path.display(),
                };
                rrg::Parcel::new(rrg::Sink::Abort, request_file.abort())
                    .send_unaccounted(comms);

                match request_file.remove() {
                    Ok(()) => {
                        info! {
                            "request file at '{}' removed",
                            request_file_path.display(),
                        }
                    }
                    Err(error) => {
                        error! {
                            "could not remove request file at '{}': {error}",
                            request_file_path.display(),
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // This is fine, we actually expect the file to not be there
                // at almost all times.
            }
            Err(error) => {
                error! {
                    "could not open the request file at '{}': {error}",
                    request_file_path.display(),
                }
            }
        }
    }

    // TODO(@panhania): Remove once no longer needed.
    if args.ping_rate > std::time::Duration::ZERO {
        std::thread::spawn(move || {
            info!("starting the pinging thread");

            for seq in 0.. {
                info!("sending a ping message (seq: {seq})");

                rrg::Parcel::new(rrg::Sink::Ping, rrg::Ping {
                    sent: std::time::SystemTime::now(),
                    seq,
                }).send_unaccounted(comms);

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

    for message in comms.receiver()
        .with_heartbeat(args.heartbeat_rate)
    {
        // TODO(https://github.com/rust-lang/rust/issues/61695): Make more
        // readable once `unwrap_infallible` is stable.
        let message = match message {
            Ok(message) => message,
            Err(error) => panic!("failed to receive Fleetspeak message: {error}"),
        };

        if message.service != "GRR" {
            let service = &message.service;
            warn!("request send by service '{service}' (instead of 'GRR')");
        }
        if message.kind.as_deref() != Some("rrg.Request") {
            match &message.kind {
                Some(kind) => warn!("request with unexpected kind '{kind}'"),
                None => warn!("request with unspecified kind"),
            }
        }

        let request = match rrg::RequestUnvalidated::parse(&message) {
            Ok(request) => request,
            Err(error) => {
                error!("malformed request: {error}");
                continue
            }
        };
        info!("received request '{}'", request.id());

        let request_file = args.request_file.as_ref().and_then(|request_file_path| {
            match rrg::abort::create_request_file(request_file_path, request.id()) {
                Ok(request_file) => {
                    info! {
                        "created request file at '{}'",
                        request_file_path.display(),
                    };

                    Some(request_file)
                }
                Err(error) => {
                    error! {
                        "could not create request file at '{}': {error}",
                        request_file_path.display(),
                    }

                    None
                }
            }
        });

        rrg::session::FleetspeakSession::dispatch(comms, &args, filestore.as_ref(), request);

        if let Some(request_file) = request_file {
            match request_file.remove() {
                Ok(()) => (),
                Err(error) => error!("could not delete request file: {error}"),
            }
        }
    }

    info!("shutting down");
}
