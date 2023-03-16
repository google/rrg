// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Wrapper types for low-level communication messages.
//!
//! At the bottom there is only one message type that GRR understands and uses
//! for all sorts of purposes. This is not a great situation to be in or reason
//! about, so in RRG we introduce new abstractions above this type:
//!
//!   * [`Request`]: A request message to execute some action.
//!   * [`Reply`]: A response message with an item that the action yielded.
//!   * [`Status`]: A response message with summary of action execution.
//!   * [`Parcel`]: A response message not associated with any particular flow.
//!
//! [`Request`]: crate::message::Request
//! [`Reply`]: crate::message::Reply
//! [`Status`]: crate::message::Status
//! [`Parcel`]: crate::message::Parcel

mod fleetspeak;
mod request;
mod response;
mod sink;

pub use response::{Reply, Status, ResponseBuilder, ResponseId};
