// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::convert::TryInto;

use crate::action;
use crate::message;
use crate::session;

pub struct Response<R: action::Response> {
    pub session_id: String,
    pub request_id: Option<u64>,
    pub response_id: Option<u64>,
    pub data: R,
}

pub struct Status {
    pub session_id: String,
    pub request_id: u64,
    pub result: session::Result<()>,
}

impl<R: action::Response> Response<R> {

    pub fn send(self) -> Result<(), prost::EncodeError> {
        let message = self.try_into()?;
        message::send(message);

        Ok(())
    }
}

impl<R: action::Response> TryInto<rrg_proto::GrrMessage> for Response<R> {

    type Error = prost::EncodeError;

    fn try_into(self) -> Result<rrg_proto::GrrMessage, prost::EncodeError> {
        let mut data = Vec::new();
        prost::Message::encode(&self.data.into_proto(), &mut data)?;

        Ok(rrg_proto::GrrMessage {
            session_id: Some(self.session_id),
            response_id: self.response_id,
            request_id: self.request_id,
            r#type: Some(rrg_proto::grr_message::Type::Message.into()),
            args_rdf_name: R::RDF_NAME.map(String::from),
            args: Some(data),
            ..Default::default()
        })
    }
}

impl TryInto<rrg_proto::GrrMessage> for Status {

    type Error = prost::EncodeError;

    fn try_into(self) -> Result<rrg_proto::GrrMessage, prost::EncodeError> {
        let status = match self.result {
            Ok(()) => rrg_proto::GrrStatus {
                status: Some(rrg_proto::grr_status::ReturnedStatus::Ok.into()),
                ..Default::default()
            },
            Err(error) => rrg_proto::GrrStatus {
                status: Some(rrg_proto::grr_status::ReturnedStatus::GenericError.into()),
                error_message: Some(error.to_string()),
                ..Default::default()
            },
        };

        let mut data = Vec::new();
        prost::Message::encode(&status, &mut data)?;

        Ok(rrg_proto::GrrMessage {
            session_id: Some(self.session_id),
            response_id: Some(self.request_id),
            r#type: Some(rrg_proto::grr_message::Type::Status.into()),
            args_rdf_name: Some(String::from("GrrStatus")),
            args: Some(data),
            ..Default::default()
        })
    }
}
