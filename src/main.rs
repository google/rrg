// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use rrg::action;
use rrg::session;
use rrg::opts::{self, Opts};

fn main() {
    let opts = opts::from_args();
    init(&opts);

    log::info!("sending Fleetspeak startup information");
    fleetspeak::startup(env!("CARGO_PKG_VERSION"))
        .expect("failed to initialize Fleetspeak connection");

    log::info!("sending RRG startup information");
    match action::startup::handle(&mut session::Adhoc, ()) {
        Err(error) => {
            log::error!("failed to collect startup information: {}", error);
        }
        Ok(()) => {
            log::info!("successfully sent startup information");
        }
    }

    log::info!("listening for messages");
    rrg::listen(&opts);
}

fn init(_: &Opts) {
    rrg::log::init();
}
