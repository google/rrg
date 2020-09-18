// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        ::log::error!(target: "rrg", $($arg)*);
    }
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        ::log::warn!(target: "rrg", $($arg)*);
    }
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        ::log::info!(target: "rrg", $($arg)*);
    }
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        ::log::debug!(target: "rrg", $($arg)*);
    }
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        ::log::trace!(target: "rrg", $($arg)*);
    }
}
