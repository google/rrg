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

    // TODO(@panhania): Remove once no longer needed.
    if args.ping_rate > std::time::Duration::ZERO {
        std::thread::spawn(move || {
            info!("starting the pinging thread");

            for seq in 0.. {
                info!("sending a ping message (seq: {seq})");

                rrg::Parcel::new(rrg::Sink::Ping, rrg::ping::Ping {
                    sent: std::time::SystemTime::now(),
                    seq,
                }).send_unaccounted();

                std::thread::sleep(args.ping_rate);
            }
        });
    } else {
        info!("pinging thread is disabled");
    }

    info!("listening for messages");
    rrg::listen(&args);
}
