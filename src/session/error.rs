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
    /// A required field of a proto message is missing.
    MissingField(&'static str),
    /// An error occurred when decoding bytes of a proto message.
    Decode(prost::DecodeError),
}

impl Display for ParseError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use ParseError::*;

        match *self {
            MissingField(name) => {
                write!(fmt, "required field is missing: {}", name)
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
            MissingField(_) => None,
            Decode(ref error) => Some(error),
        }
    }
}

impl From<prost::DecodeError> for ParseError {

    fn from(error: prost::DecodeError) -> ParseError {
        ParseError::Decode(error)
    }
}
