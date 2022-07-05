// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

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

fn init(_: &Opts) {
    env_logger::init();
}
