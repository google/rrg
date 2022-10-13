// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::fmt::{Debug, Display, Formatter};
use regex::Error as RegexError;

// TODO(panhania@): Migrate to error kind design.
/// An error type for failures that can occur during a session.
#[derive(Debug)]
pub enum Error {
    /// Action-specific failure.
    Action(Box<dyn std::error::Error>),
    /// Attempted to call an unknown or not implemented action.
    Dispatch(String),
    /// An error occurred when parsing a proto message.
    Parse(crate::action::ParseArgsError),
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
            Parse(ref error) => Some(error),
        }
    }
}

impl From<crate::action::ParseArgsError> for Error {

    fn from(error: crate::action::ParseArgsError) -> Error {
        Error::Parse(error)
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

#[derive(Debug)]
pub struct RegexParseError {
    /// Raw data of the string which could not be converted to Regex.
    pub raw_data: Vec<u8>,
    /// Error message caught during the conversion.
    pub error: RegexError,
}

impl Display for RegexParseError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "Regex parse error happened on parsing '{:?}'. \
                     Regex error: '{}'",
               self.raw_data,
               self.error.to_string())
    }
}

impl std::error::Error for RegexParseError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<RegexParseError> for ParseError {

    fn from(error: RegexParseError) -> ParseError {
        ParseError::malformed(error)
    }
}

/// An error type for situations where proto enum has a value for which
/// the definition is not known.
#[derive(Debug)]
pub struct UnknownEnumValueError {
    /// A name of the enum field having unknown enum value.
    pub name: &'static str,

    /// An enum value, which definition is not known.
    pub value: i32,
}

impl Display for UnknownEnumValueError {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "protobuf enum '{}' has unrecognised value: '{}'",
               self.name, self.value)
    }
}

impl std::error::Error for UnknownEnumValueError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<UnknownEnumValueError> for ParseError {

    fn from(error: UnknownEnumValueError) -> ParseError {
        ParseError::malformed(error)
    }
}
