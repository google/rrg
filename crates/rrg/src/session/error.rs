// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

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
    /// The requested action is not known.
    UnknownAction,
    /// The requested action is not supported.
    UnsupportedAction,
    /// The arguments given for the action were malformed.
    InvalidArgs,
    // strictly necessary, we can be consistent here and rename this variant.
    /// The action execution failed.
    ActionFailure,
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
            kind: ErrorKind::ActionFailure,
            error: Box::new(error),
        }
    }

    /// Converts an unknown action value to a session error.
    pub fn unknown_action(action: crate::request::UnknownAction) -> Error {
        Error {
            kind: ErrorKind::UnknownAction,
            error: Box::new(UnknownActionError { action }),
        }
    }

    /// Converts an action that is not supported to a session error.
    pub fn unsupported_action(action: crate::request::Action) -> Error {
        Error {
            kind: ErrorKind::UnsupportedAction,
            error: Box::new(UnsupportedActionError { action }),
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ErrorKind::*;

        match self.kind {
            UnknownAction => {
                // `self.error` is an instance of `UnknownActionError` which
                // contains meaningful message, we don't need to provide it
                // ourselves here.
                write!(fmt, "{}", self.error)
            }
            UnsupportedAction => {
                // Same as with `UnknownAction` variant, the `self.error` is an
                // instance of `UnsupportedActionError` and has enough details.
                write!(fmt, "{}", self.error)
            }
            InvalidArgs => {
                write!(fmt, "invalid action arguments: {}", self.error)
            }
            ActionFailure => {
                write!(fmt, "action execution failed: {}", self.error)
            }
        }
    }
}

impl std::error::Error for Error {

    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self.error.as_ref())
    }
}

impl From<crate::request::ParseArgsError> for Error {

    fn from(error: crate::request::ParseArgsError) -> Error {
        Error {
            kind: ErrorKind::InvalidArgs,
            error: Box::new(error),
        }
    }
}

impl From<Error> for rrg_proto::v2::rrg::Status_Error {

    fn from(error: Error) -> rrg_proto::v2::rrg::Status_Error {
        let mut proto = rrg_proto::v2::rrg::Status_Error::new();
        proto.set_field_type(error.kind.into());
        proto.set_message(error.to_string());

        proto
    }
}

impl From<ErrorKind> for rrg_proto::v2::rrg::Status_Error_Type {

    fn from(kind: ErrorKind) -> rrg_proto::v2::rrg::Status_Error_Type {
        use ErrorKind::*;

        match kind {
            UnknownAction => Self::UNKNOWN_ACTION,
            UnsupportedAction => Self::UNSUPPORTED_ACTION,
            InvalidArgs => Self::INVALID_ARGS,
            ActionFailure => Self::ACTION_FAILURE,
        }
    }
}

/// An error type for cases when the action specified in the request is unknown.
#[derive(Debug)]
struct UnknownActionError {
    action: crate::request::UnknownAction,
}

impl std::fmt::Display for UnknownActionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "unknown action '{}'", self.action)
    }
}

impl std::error::Error for UnknownActionError {
}

/// An error type for when the action specified in the request is not supported.
#[derive(Debug)]
struct UnsupportedActionError {
    action: crate::request::Action,
}

impl std::fmt::Display for UnsupportedActionError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "unsupported action '{}'", self.action)
    }
}

impl std::error::Error for UnsupportedActionError {
}
