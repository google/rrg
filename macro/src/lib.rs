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

/// Acknowledges a possible error and transforms the value into optional.
///
/// The `ack` macro will evaluate given expression that returns a result and,
/// in case of an error, log it at the specified level. Then, the errors is
/// simply discarded at the value is transformed into an `Option`.
///
/// This macro can be useful in cases where errors are not critical and are to
/// some extent expected. Just throwing them away without logging is not always
/// a good option, since they may include some useful information.
///
/// # Examples
///
/// ```no_run
/// # use rrg_macro::ack;
/// use std::path::PathBuf;
///
/// let profile = ack! {
///     std::env::var("HOME"),
///     error: "home folder not specified"
/// }.and_then(|home| ack! {
///     std::fs::read([&home, ".profile"].iter().collect::<PathBuf>()),
///     error: "failed to read the profile file"
/// });
///
/// if let Some(profile) = profile {
///     println!("size of the profile file: {}", profile.len());
/// }
/// ```
#[macro_export]
macro_rules! ack {
    { $expr:expr, $level:ident: $message:literal } => {
        match $expr {
            Ok(value) => Some(value),
            Err(err) => {
                ::rrg_macro::$level!(concat!($message, ": {}"), err);
                None
            },
        }
    };
}
