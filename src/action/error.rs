// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// The error type for cases when action argument parsing fails.
#[derive(Debug)]
pub struct ParseArgsError {
    /// A corresponding [`ParseArgsErrorKind`] of this error.
    kind: ParseArgsErrorKind,
    /// A detailed payload associated with the error.
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl ParseArgsError {

    /// Creates a new error instance caused by some invalid field error.
    pub fn invalid_field<E>(error: E) -> ParseArgsError
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidField,
            error: Box::new(error),
        }
    }

    /// Returns the corresponding [`ParseArgsErrorKind`] of this error.
    pub fn kind(&self) -> ParseArgsErrorKind {
        self.kind
    }
}

/// Kinds of errors that can happen when parsing action arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseArgsErrorKind {
    /// The serialized message with arguments was impossible to deserialize.
    InvalidProto,
    // TODO(panhania@): Augment with field name.
    /// One of the fields of the arguments struct is invalid.
    InvalidField,
}

impl ParseArgsErrorKind {

    fn as_str(&self) -> &'static str {
        use ParseArgsErrorKind::*;

        match *self {
            InvalidProto => "invalid serialized protobuf message",
            InvalidField => "invalid argument field",
        }
    }
}

impl std::fmt::Display for ParseArgsError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}: {}", self.kind.as_str(), self.error)
    }
}

impl std::error::Error for ParseArgsError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

impl From<protobuf::ProtobufError> for ParseArgsError {

    fn from(error: protobuf::ProtobufError) -> Self {
        ParseArgsError {
            kind: ParseArgsErrorKind::InvalidProto,
            error: Box::new(error),
        }
    }
}

/// The error type for cases when there was a request to run an unknown action.
#[derive(Debug)]
pub struct UnknownActionError {
    action_name: String,
}

impl UnknownActionError {

    pub fn new<S: Into<String>>(action_name: S) -> UnknownActionError {
        UnknownActionError {
            action_name: action_name.into(),
        }
    }
}

impl std::fmt::Display for UnknownActionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "unknown action '{}'", self.action_name)
    }
}

impl std::error::Error for UnknownActionError {
}

/// The error type for cases when action dispatch (or execution) fails.
#[derive(Debug)]
pub struct DispatchError {
    /// A detailed error object.
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl std::fmt::Display for DispatchError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}", self.error)
    }
}

impl std::error::Error for DispatchError {

    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self.error.as_ref())
    }
}

impl From<ParseArgsError> for DispatchError {

    fn from(error: ParseArgsError) -> DispatchError {
        DispatchError {
            error: Box::new(error),
        }
    }
}

impl From<UnknownActionError> for DispatchError {

    fn from(error: UnknownActionError) -> DispatchError {
        DispatchError {
            error: Box::new(error),
        }
    }
}

impl From<crate::session::Error> for DispatchError {

    fn from(error: crate::session::Error) -> DispatchError {
        DispatchError {
            error: Box::new(error),
        }
    }
}
