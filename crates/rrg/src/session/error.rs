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
    error: Box<dyn std::error::Error>,
}

/// Kinds of errors that can happen during a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The action request was invalid.
    InvalidRequest(crate::request::ParseRequestErrorKind),
    /// The requested action is not supported.
    UnsupportedAction,
    /// The arguments given for the action were malformed.
    InvalidArgs,
    /// The action execution failed.
    ActionFailure,
    /// Filter evaluation on action result failed.
    FilterFailure,
    /// Action execution crossed the allowed network bytes limit.
    NetworkBytesLimitExceeded,
    /// Action execution crossed the allowed real (wall) time limit.
    RealTimeLimitExceeded,
}

impl Error {

    /// Converts an arbitrary action-issued error to a session error.
    ///
    /// This function should be used to construct session errors from action
    /// specific error types and propagate them further in the session pipeline.
    pub fn action<E>(error: E) -> Error
    where
        E: std::error::Error + 'static,
    {
        Error {
            kind: ErrorKind::ActionFailure,
            error: Box::new(error),
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
            InvalidRequest(_) => {
                // `self.error` is an instance of `ParseRequestError` which
                // contains meaningful message, we don't need to provide it
                // ourselves here.
                write!(fmt, "{}", self.error)
            }
            UnsupportedAction => {
                // Same as with `InvalidRequest` variant, the `self.error` is an
                // instance of `UnsupportedActionError` and has enough details.
                write!(fmt, "{}", self.error)
            }
            InvalidArgs => {
                write!(fmt, "invalid action arguments: {}", self.error)
            }
            ActionFailure => {
                write!(fmt, "action execution failed: {}", self.error)
            }
            FilterFailure => {
                write!(fmt, "filter evaluation failed: {}", self.error)
            }
            NetworkBytesLimitExceeded => {
                write!(fmt, "network bytes limit exceeded: {}", self.error)
            }
            RealTimeLimitExceeded => {
                write!(fmt, "real time limit exceeded: {}", self.error)
            }
        }
    }
}

impl std::error::Error for Error {

    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self.error.as_ref())
    }
}

impl From<crate::request::ParseRequestError> for Error {

    fn from(error: crate::request::ParseRequestError) -> Error {
        Error {
            kind: ErrorKind::InvalidRequest(error.kind()),
            error: Box::new(error),
        }
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

impl From<crate::request::FilterError> for Error {

    fn from(error: crate::request::FilterError) -> Error {
        Error {
            kind: ErrorKind::FilterFailure,
            error: Box::new(error),
        }
    }
}

impl From<Error> for rrg_proto::rrg::status::Error {

    fn from(error: Error) -> rrg_proto::rrg::status::Error {
        let mut proto = rrg_proto::rrg::status::Error::new();
        proto.set_type(error.kind.into());
        proto.set_message(error.to_string());

        proto
    }
}

impl From<ErrorKind> for rrg_proto::rrg::status::error::Type {

    fn from(kind: ErrorKind) -> rrg_proto::rrg::status::error::Type {
        use ErrorKind::*;

        match kind {
            InvalidRequest(kind) => kind.into(),
            UnsupportedAction => Self::UNSUPPORTED_ACTION,
            InvalidArgs => Self::INVALID_ARGS,
            ActionFailure => Self::ACTION_FAILURE,
            FilterFailure => Self::FILTER_FAILURE,
            NetworkBytesLimitExceeded => Self::NETWORK_BYTES_SENT_LIMIT_EXCEEDED,
            RealTimeLimitExceeded => Self::REAL_TIME_LIMIT_EXCEEDED,
        }
    }
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

/// An error type raised when the network bytes limit has been exceeded.
#[derive(Debug)]
pub struct NetworkBytesLimitExceededError {
    /// Number of bytes we actually sent.
    pub network_bytes_sent: u64,
    /// Number of bytes we were allowed to send.
    pub network_bytes_limit: u64,
}

impl std::fmt::Display for NetworkBytesLimitExceededError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write! {
            fmt,
            "sent {} bytes out of allowed {}",
            self.network_bytes_sent,
            self.network_bytes_limit,
        }
    }
}

impl std::error::Error for NetworkBytesLimitExceededError {
}

impl From<NetworkBytesLimitExceededError> for Error {

    fn from(error: NetworkBytesLimitExceededError) -> Error {
        Error {
            kind: ErrorKind::NetworkBytesLimitExceeded,
            error: Box::new(error),
        }
    }
}

/// An error type raised when the real (wall) time limit has been exceeded.
#[derive(Debug)]
pub struct RealTimeLimitExceededError {
    /// Amount of real time we actually spent on executing the action.
    pub real_time_spent: std::time::Duration,
    /// Amount of real time we were allowed to spend on executing the action.
    pub real_time_limit: std::time::Duration,
}

impl std::fmt::Display for RealTimeLimitExceededError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write! {
            fmt,
            "spent real time {} out of allowed {}",
            humantime::format_duration(self.real_time_spent),
            humantime::format_duration(self.real_time_limit),
        }
    }
}

impl std::error::Error for RealTimeLimitExceededError {
}

impl From<RealTimeLimitExceededError> for Error {

    fn from(error: RealTimeLimitExceededError) -> Error {
        Error {
            kind: ErrorKind::RealTimeLimitExceeded,
            error: Box::new(error),
        }
    }
}
