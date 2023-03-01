// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Filesystem inspection functionalities.

// TODO(@panhania): Define common interface for all platforms and hide these
// modules.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_family = "unix")]
pub mod unix;
