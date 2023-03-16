// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::fmt::{Debug, Display, Formatter};

/// An error type for failures that can occur during a session.
#[derive(Debug)]
pub struct Error {
    /// A corresponding [`ErrorKind`] of this error.
    kind: ErrorKind,
    /// A detailed error object.
    error: Box<dyn std::error::Error + Send + Sync>,
}

/// Kinds of errors that can happen during a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The arguments given for the action were malformed.
    InvalidArgs,
    /// The action execution failed.
    ExecutionFailure,
}

impl Error {

    /// Converts an arbitrary action-issued error to a session error.
    ///
    /// This function should be used to construct session errors from action
    /// specific error types and propagate them further in the session pipeline.
    pub fn action<E>(error: E) -> Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error {
            kind: ErrorKind::ExecutionFailure,
            error: Box::new(error),
        }
    }
}

impl ErrorKind {

    fn as_str(&self) -> &'static str {
        use ErrorKind::*;

        match *self {
            InvalidArgs => "invalid action arguments",
            ExecutionFailure => "action execution failed",
        }
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind.as_str(), self.error)
    }
}

impl std::error::Error for Error {

    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self.error.as_ref())
    }
}

impl From<crate::action::ParseArgsError> for Error {

    fn from(error: crate::action::ParseArgsError) -> Error {
        Error {
            kind: ErrorKind::InvalidArgs,
            error: Box::new(error),
        }
    }
}
