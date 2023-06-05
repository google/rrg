// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Index of deprecated RRG actions that follow the old protocol.
//!
//! Code from this module is supposed to be migrated to use the new protocol and
//! be completely removed at some point.

#[cfg(feature = "action-filesystems")]
#[cfg(target_os = "linux")]
pub mod filesystems;

#[cfg(feature = "action-finder")]
pub mod finder;

#[cfg(feature = "action-insttime")]
mod insttime;

#[cfg(feature = "action-interfaces")]
#[cfg(target_family = "unix")]
pub mod interfaces;

#[cfg(feature = "action-listdir")]
pub mod listdir;

#[cfg(feature = "action-network")]
pub mod network;

#[cfg(feature = "action-stat")]
pub mod stat;
