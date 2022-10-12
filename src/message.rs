// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO: Write top-level documentation for this module (and its submodules).

// TODO(panhania@): Hide the `fleetspeak` submodule.
pub mod fleetspeak;
mod request;
mod response;
pub mod sink;

pub use request::{Request, RequestId, ReceiveRequestError};
pub use response::{Item, Status, ResponseBuilder, ResponseId};
