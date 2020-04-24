// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::convert::TryFrom;

use crate::session;
use crate::action;

#[derive(Clone, Debug)]
pub struct Demand {
    pub action: String,
    pub header: Header,
    pub payload: Payload,
}

#[derive(Clone, Debug)]
pub struct Header {
    pub session_id: String,
    pub request_id: u64,
}

#[derive(Clone, Debug)]
pub struct Payload {
    pub data: Option<Vec<u8>>,
}

impl Payload {

    pub fn parse<R>(&self) -> Result<R, session::ParseError>
    where
        R: action::Request,
    {
        let proto = match &self.data {
            Some(ref bytes) => prost::Message::decode(&bytes[..])?,
            None => Default::default(),
        };

        Ok(R::from_proto(proto))
    }
}

impl TryFrom<rrg_proto::GrrMessage> for Demand {

    type Error = session::ParseError;

    fn try_from(message: rrg_proto::GrrMessage) -> Result<Demand, Self::Error> {
        use session::ParseError::*;

        let header = Header {
            session_id: message.session_id.ok_or(MissingField("session id"))?,
            request_id: message.request_id.ok_or(MissingField("request id"))?,
        };

        Ok(Demand {
            action: message.name.ok_or(MissingField("action name"))?,
            header: header,
            payload: Payload {
                data: message.args,
            },
        })
    }
}

