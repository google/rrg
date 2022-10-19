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

/// The error type for cases when action dispatch (or execution) fails.
#[derive(Debug)]
pub struct DispatchError {
    /// A corresponding [`DispatchErrorKind`] of this error.
    pub(crate) kind: DispatchErrorKind,
    /// A detailed error object.
    pub(crate) error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// Kinds of errors that can happen when dispatching an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DispatchErrorKind {
    /// The action handler is unknown or does not exist yet.
    UnknownAction(&'static str),
    /// The action arguments were invalid.
    InvalidArgs,
    /// An error occured during a session.
    SessionFailure,
}

impl std::fmt::Display for DispatchError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error {
            Some(ref error) => write!(fmt, "{}: {}", self.kind, error),
            None => write!(fmt, "{}", self.kind),
        }
    }
}

impl std::error::Error for DispatchError {

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.error.as_deref().map(|error| error as &_)
    }
}

impl std::fmt::Display for DispatchErrorKind {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use DispatchErrorKind::*;

        match *self {
            UnknownAction(name) => write!(fmt, "unknown action '{}'", name),
            InvalidArgs => write!(fmt, "invalid action arguments"),
            SessionFailure => write!(fmt, "session evaluation failure"),
        }
    }
}

impl From<ParseArgsError> for DispatchError {

    fn from(error: ParseArgsError) -> DispatchError {
        DispatchError {
            kind: DispatchErrorKind::InvalidArgs,
            error: Some(Box::new(error)),
        }
    }
}

impl From<crate::session::Error> for DispatchError {

    fn from(error: crate::session::Error) -> DispatchError {
        DispatchError {
            kind: DispatchErrorKind::SessionFailure,
            error: Some(Box::new(error)),
        }
    }
}
