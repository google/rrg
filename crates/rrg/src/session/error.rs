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

/// An error type for failures that can occur when parsing proto messages.
#[derive(Debug)]
pub enum ParseError {
    /// An error occurred because the decoded proto message was malformed.
    Malformed(Box<dyn std::error::Error + Send + Sync>),
    /// An error occurred when decoding bytes of a proto message.
    Decode(protobuf::ProtobufError),
}

impl ParseError {

    /// Converts a detailed error indicating a malformed proto to `ParseError`.
    ///
    /// This is just a convenience function for lifting custom error types that
    /// contain more specific information to generic `ParseError`.
    pub fn malformed<E>(error: E) -> ParseError
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        ParseError::Malformed(error.into())
    }
}

impl Display for ParseError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use ParseError::*;

        match *self {
            Malformed(ref error) => {
                write!(fmt, "invalid proto message: {}", error)
            }
            Decode(ref error) => {
                write!(fmt, "failed to decode proto message: {}", error)
            }
        }
    }
}

impl std::error::Error for ParseError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            Malformed(ref error) => Some(error.as_ref()),
            Decode(ref error) => Some(error),
        }
    }
}

impl From<protobuf::ProtobufError> for ParseError {

    fn from(error: protobuf::ProtobufError) -> ParseError {
        ParseError::Decode(error)
    }
}

/// An error type for situations where time micros cannot be converted
/// to `std::time::SystemTime`.
#[derive(Debug)]
pub struct TimeMicrosConversionError {
    /// Time micros value causing the conversion error.
    pub micros: u64,
}

impl Display for TimeMicrosConversionError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "cannot convert micros to std::time::SystemTime: {}", self.micros)
    }
}

impl std::error::Error for TimeMicrosConversionError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<TimeMicrosConversionError> for ParseError {

    fn from(error: TimeMicrosConversionError) -> ParseError {
        ParseError::malformed(error)
    }
}
