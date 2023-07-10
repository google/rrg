// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::info;

fn main() {
    let args = rrg::args::from_env_args();
    rrg::init(&args);

    info!("sending Fleetspeak startup information");
    fleetspeak::startup(env!("CARGO_PKG_VERSION"));

    info!("sending RRG startup information");
    rrg::startup();

    info!("listening for messages");
    rrg::listen(&args);
}
