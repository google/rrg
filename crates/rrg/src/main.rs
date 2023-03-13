// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::{info, error};
use rrg::args::Args;

fn main() {
    let args = rrg::args::from_env_args();
    init(&args);

    info!("sending Fleetspeak startup information");
    fleetspeak::startup(env!("CARGO_PKG_VERSION"))
        .expect("failed to initialize Fleetspeak connection");

    info!("sending RRG startup information");
    match rrg::startup::send() {
        Err(error) => error!("failed to collect startup information: {error}"),
        Ok(()) => info!("successfully sent startup information"),
    }

    info!("listening for messages");
    rrg::listen(&args);
}

fn init(args: &Args) {
    rrg::log::init(args);
}
