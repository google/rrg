// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::io::Result;
use std::time::Duration;

#[derive(structopt_derive::StructOpt)]
#[structopt(name = "RRG", about = "A GRR agent rewritten in Rust.")]
struct Opts {
}

fn main() -> Result<()> {
    <Opts as structopt::StructOpt>::from_args();

    fleetspeak::startup(env!("CARGO_PKG_VERSION"))?;

    loop {
        let packet = fleetspeak::collect(Duration::from_secs(1))?;
        handle(packet.data);
    }
}

fn handle(message: rrg_proto::GrrMessage) {
    match message.name {
        Some(name) => println!("requested to execute the '{}' action", name),
        None => eprintln!("missing action name to execute"),
    }
}
