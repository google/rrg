// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Action(Box<dyn std::error::Error>),
    Send(std::io::Error),
    Encode(prost::EncodeError),
}

impl Error {

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
            Send(ref error) => {
                write!(fmt, "Fleetspeak message delivery error: {}", error)
            }
            Encode(ref error) => {
                write!(fmt, "failure during encoding proto message: {}", error)
            }
        }
    }
}

impl std::error::Error for Error {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Action(ref error) => Some(error.as_ref()),
            Send(ref error) => Some(error),
            Encode(ref error) => Some(error),
        }
    }
}

impl From<fleetspeak::WriteError> for Error {

    fn from(error: fleetspeak::WriteError) -> Error {
        use fleetspeak::WriteError::*;
        match error {
            Output(error) => Error::Send(error),
            Encode(error) => Error::Encode(error),
        }
    }
}

impl From<prost::EncodeError> for Error {

    fn from(error: prost::EncodeError) -> Error {
        Error::Encode(error)
    }
}
