// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO: Write top-level documentation for this module (and its submodules).

mod fleetspeak;
mod request;
mod response;
mod sink;

pub use request::{Request, RequestId, ReceiveRequestError};
pub use response::{Reply, Status, Parcel, ResponseBuilder, ResponseId};
pub use sink::{Sink};
