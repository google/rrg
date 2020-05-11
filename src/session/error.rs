// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::fmt::{Display, Formatter};

/// An error type for failures that can occur during a session.
#[derive(Debug)]
pub enum Error {
    /// Action-specific failure.
    Action(Box<dyn std::error::Error>),
    /// Attempted to call an unknown or not implemented action.
    Dispatch(String),
    /// An error occurred when encoding bytes of a proto message.
    Encode(prost::EncodeError),
    /// An error occurred when parsing a proto message.
    Parse(ParseError),
}

impl Error {

    /// Converts an arbitrary action-issued error to a session error.
    ///
    /// This function should be used to construct session errors from action
    /// specific error types and propagate them further in the session pipeline.
    pub fn action<E>(error: E) -> Error
    where
        E: std::error::Error + 'static
    {
        Error::Action(Box::new(error))
    }
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
            Action(ref error) => {
                write!(fmt, "action error: {}", error)
            }
            Dispatch(ref name) if name.is_empty() => {
                write!(fmt, "missing action")
            }
            Dispatch(ref name) => {
                write!(fmt, "unknown action: {}", name)
            }
            Encode(ref error) => {
                write!(fmt, "failure during encoding proto message: {}", error)
            }
            Parse(ref error) => {
                write!(fmt, "malformed proto message: {}", error)
            }
        }
    }
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Action(ref error) => Some(error.as_ref()),
            Dispatch(_) => None,
            Encode(ref error) => Some(error),
            Parse(ref error) => Some(error),
        }
    }
}

impl From<prost::EncodeError> for Error {

    fn from(error: prost::EncodeError) -> Error {
        Error::Encode(error)
    }
}

impl From<ParseError> for Error {

    fn from(error: ParseError) -> Error {
        Error::Parse(error)
    }
}

/// An error type for failures that can occur when parsing proto messages.
#[derive(Debug)]
pub enum ParseError {
    /// An error occurred because the decoded proto message was malformed.
    Malformed(Box<dyn std::error::Error + Send + Sync>),
    /// An error occurred when decoding bytes of a proto message.
    Decode(prost::DecodeError),
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

impl From<prost::DecodeError> for ParseError {

    fn from(error: prost::DecodeError) -> ParseError {
        ParseError::Decode(error)
    }
}

/// An error type for situations where required proto field is missing.
#[derive(Debug)]
pub struct MissingFieldError {
    /// A name of the missing field.
    name: &'static str,
}

impl MissingFieldError {

    /// Creates a new error indicating that required field `name` is missing.
    pub fn new(name: &'static str) -> MissingFieldError {
        MissingFieldError {
            name: name,
        }
    }
}

impl Display for MissingFieldError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "required field '{}' is missing", self.name)
    }
}

impl std::error::Error for MissingFieldError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<MissingFieldError> for ParseError {

    fn from(error: MissingFieldError) -> ParseError {
        ParseError::malformed(error)
    }
}
