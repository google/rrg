// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::convert::TryFrom;

use crate::session;
use crate::action;

/// Untyped request to execute an action.
///
/// It is called "demand" rather than "request" here, as requests should be more
/// structured. The demand is only a slightly more structured variant of the
/// raw Protocol Buffers message with actual request still being in a serialized
/// form.
///
/// The request has to stay serialized because, until dispatched to a specific
/// handler, the type into which it should be deserialized remains unknown.
#[derive(Clone, Debug)]
pub struct Demand {
    /// A name of the action to execute.
    pub action: String,
    /// A demand metadata.
    pub header: Header,
    /// Serialized action request.
    pub payload: Payload,
}

/// Metadata about the demand issued by the server.
#[derive(Clone, Debug)]
pub struct Header {
    /// A server-issued session identifier (usually corresponds to a flow).
    pub session_id: String,
    /// A server-issued request identifier.
    pub request_id: u64,
}

/// Serialized request data for the action handler.
#[derive(Clone, Debug)]
pub struct Payload {
    /// Raw bytes of the serialized request.
    pub data: Option<Vec<u8>>,
}

impl Payload {

    /// Parses the serialized data to a specific request type.
    ///
    /// If the payload contains no data, a default request instance is created.
    ///
    /// If the data is malformed and fails to correctly parse to a specific
    /// request instance, an error is returned.
    pub fn parse<R>(&self) -> Result<R, session::ParseError>
    where
        R: action::Request,
    {
        let proto = match &self.data {
            Some(ref bytes) => protobuf::parse_from_bytes(bytes)?,
            None => Default::default(),
        };

        R::from_proto(proto)
    }
}

impl TryFrom<rrg_proto::jobs::GrrMessage> for Demand {

    type Error = session::ParseError;

    fn try_from(mut message: rrg_proto::jobs::GrrMessage) -> Result<Demand, Self::Error> {
        let session_id = if message.has_session_id() {
            message.take_session_id()
        } else {
            return Err(session::MissingFieldError::new("session_id").into());
        };

        let request_id = if message.has_request_id() {
            message.get_request_id()
        } else {
            return Err(session::MissingFieldError::new("request_id").into());
        };

        let action = if message.has_name() {
            message.take_name()
        } else {
            return Err(session::MissingFieldError::new("action name").into());
        };

        let data = if message.has_args() {
            Some(message.take_args())
        } else {
            None
        };

        Ok(Demand {
            action: action,
            header: Header {
                session_id,
                request_id,
            },
            payload: Payload {
                data,
            },
        })
    }
}
