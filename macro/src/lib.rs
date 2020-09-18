// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Logs a RRG-specific message at the error level.
///
/// # Examples
///
/// ```no_run
/// # use rrg_macro::error;
/// error!("some awkward error occured (code: {})", 42);
/// ```
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        ::log::error!(target: "rrg", $($arg)*);
    }
}

/// Logs a RRG-specific message at the warn level.
///
/// # Examples
///
/// ```no_run
/// # use rrg_macro::warn;
/// warn!("received a strange number: {}", 1337);
/// ```
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        ::log::warn!(target: "rrg", $($arg)*);
    }
}

/// Logs a RRG-specific message at the info level.
///
/// # Examples
///
/// ```no_run
/// # use rrg_macro::info;
/// info!("running as '{}'", std::env::var("USER").unwrap());
/// ```
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        ::log::info!(target: "rrg", $($arg)*);
    }
}

/// Logs a RRG-specific message at the debug level.
///
/// # Examples
///
/// ```no_run
/// # use rrg_macro::debug;
/// debug!("a bunch of very important numbers: {:?}", &[4, 8, 15, 16, 23, 42]);
/// ```
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        ::log::debug!(target: "rrg", $($arg)*);
    }
}

/// Logs a RRG-specific message at the trace level.
///
/// # Examples
///
/// ```no_run
/// # use rrg_macro::trace;
/// trace!("we are at ({}; {})", std::f32::consts::PI, std::f32::consts::E);
/// ```
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        ::log::trace!(target: "rrg", $($arg)*);
    }
}
