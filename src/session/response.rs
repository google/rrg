// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::convert::TryInto;

use crate::action;
use crate::session;

/// Individual action response.
///
/// This type can be used both for action replies (for a particular session) and
/// responses sent to sinks.
pub struct Response<R: action::Response> {
    /// A server-issued identifier, usually corresponding to a flow.
    pub session_id: String,
    /// A server-issued identifier for the current action request (if any).
    pub request_id: Option<u64>,
    /// An unique (to the current action request) identifier of the response.
    pub response_id: Option<u64>,
    /// An action-specific response.
    pub data: R,
}

/// Final session response indicating success or failure of action execution.
///
/// Each session is supposed to send this final response and communicate to the
/// server that it has finished working (whether it is because of all work that
/// was supposed to be done is done or because an error has occurred).
pub struct Status {
    /// A server-issued identifier, usually corresponding to a flow.
    pub session_id: String,
    /// A server-issued identifier for the current action request.
    pub request_id: u64,
    /// An unique (to the current action request) identifier of status response.
    pub response_id: u64,
    /// A result of action execution.
    pub result: session::Result<()>,
}

impl<R> TryInto<rrg_proto::protobuf::jobs::GrrMessage> for Response<R>
where
    R: action::Response,
{
    type Error = protobuf::ProtobufError;

    fn try_into(self) -> Result<rrg_proto::protobuf::jobs::GrrMessage, protobuf::ProtobufError> {
        let mut message = rrg_proto::protobuf::jobs::GrrMessage::new();
        message.set_session_id(self.session_id);
        // TODO: Is is really possible for us not to have the `request_id` or
        // `response_id` fields? We should take a closer look at this and likely
        // strengthen the types.
        if let Some(request_id) = self.request_id {
            message.set_request_id(request_id);
        }
        if let Some(response_id) = self.response_id {
            message.set_response_id(response_id);
        }
        message.set_field_type(rrg_proto::protobuf::jobs::GrrMessage_Type::MESSAGE);

        if let Some(rdf_name) = R::RDF_NAME {
            message.set_args_rdf_name(String::from(rdf_name));
        }
        message.set_args(protobuf::Message::write_to_bytes(&self.data.into_proto())?);

        Ok(message)
    }
}

impl<R: action::Response> TryInto<rrg_proto::GrrMessage> for Response<R> {

    type Error = protobuf::ProtobufError;

    fn try_into(self) -> Result<rrg_proto::GrrMessage, protobuf::ProtobufError> {
        let data = protobuf::Message::write_to_bytes(&self.data.into_proto())?;

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

impl TryInto<rrg_proto::protobuf::jobs::GrrMessage> for Status {

    type Error = protobuf::ProtobufError;

    fn try_into(self) -> Result<rrg_proto::protobuf::jobs::GrrMessage, protobuf::ProtobufError> {
        let mut status = rrg_proto::protobuf::jobs::GrrStatus::new();
        match self.result {
            Ok(()) => {
                status.set_status(rrg_proto::protobuf::jobs::GrrStatus_ReturnedStatus::OK);
            },
            Err(error) => {
                status.set_status(rrg_proto::protobuf::jobs::GrrStatus_ReturnedStatus::GENERIC_ERROR);
                status.set_error_message(error.to_string());
            },
        }

        let mut message = rrg_proto::protobuf::jobs::GrrMessage::new();
        message.set_session_id(self.session_id);
        message.set_request_id(self.request_id);
        message.set_response_id(self.response_id);
        message.set_field_type(rrg_proto::protobuf::jobs::GrrMessage_Type::STATUS);

        message.set_args(protobuf::Message::write_to_bytes(&status)?);
        message.set_args_rdf_name(String::from("GrrStatus"));

        Ok(message)
    }
}

impl TryInto<rrg_proto::GrrMessage> for Status {

    type Error = prost::EncodeError;

    fn try_into(self) -> Result<rrg_proto::GrrMessage, prost::EncodeError> {
        use rrg_proto::grr_status::ReturnedStatus;

        let status = match self.result {
            Ok(()) => rrg_proto::GrrStatus {
                status: Some(ReturnedStatus::Ok.into()),
                ..Default::default()
            },
            Err(error) => rrg_proto::GrrStatus {
                status: Some(ReturnedStatus::GenericError.into()),
                error_message: Some(error.to_string()),
                ..Default::default()
            },
        };

        let mut data = Vec::new();
        prost::Message::encode(&status, &mut data)?;

        Ok(rrg_proto::GrrMessage {
            session_id: Some(self.session_id),
            request_id: Some(self.request_id),
            response_id: Some(self.response_id),
            r#type: Some(rrg_proto::grr_message::Type::Status.into()),
            args_rdf_name: Some(String::from("GrrStatus")),
            args: Some(data),
            ..Default::default()
        })
    }
}
