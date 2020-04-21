mod error;

use std::convert::{TryFrom, TryInto};

use fleetspeak::Packet;

use crate::action;
pub use self::error::{Error, ParseError};

pub type Result<T> = std::result::Result<T, Error>;

pub type Handler<R> = fn(&mut Action, R) -> Result<()>;

pub fn handle<R, M>(handler: Handler<R>, message: M) -> Result<()>
where
    R: action::Request,
    M: TryInto<Request<R>, Error=ParseError>,
{
    let request = message.try_into()?;

    let mut session = Action::new(request.session_id, request.request_id);
    handler(&mut session, request.data)
}

pub trait Session {
    fn send<R: action::Response>(&mut self, response: R) -> Result<()>;
}

pub struct Action {
    id: String,
    request_id: u64,
    next_response_id: u64,
}

impl Action {

    pub fn new(session_id: String, request_id: u64) -> Action {
        Action {
            id: session_id,
            request_id: request_id,
            next_response_id: 0,
        }
    }
}

impl Session for Action {

    fn send<R: action::Response>(&mut self, response: R) -> Result<()> {
        Response {
            session_id: self.id.clone(),
            request_id: Some(self.request_id),
            response_id: Some(self.next_response_id),
            data: response,
        }.send()?;

        self.next_response_id += 1;

        Ok(())
    }
}

pub struct Sink {
    id: &'static str,
}

impl Session for Sink {

    fn send<R: action::Response>(&mut self, response: R) -> Result<()> {
        Response {
            session_id: String::from(self.id),
            request_id: None,
            response_id: None,
            data: response,
        }.send()
    }
}

pub fn startup() -> Sink {
    Sink { id: "/flows/F:Startup" }
}

// TODO: This type should not be exposed.
pub struct Request<R: action::Request> {
    pub name: String,
    pub session_id: String,
    pub request_id: u64,
    pub data: R,
}

impl<R: action::Request> TryFrom<rrg_proto::GrrMessage> for Request<R> {

    type Error = ParseError;

    fn try_from(message: rrg_proto::GrrMessage)
    -> std::result::Result<Request<R>, ParseError>
    {
        use ParseError::*;

        let name = message.name.ok_or(MissingField("action name"))?;
        let session_id = message.session_id.ok_or(MissingField("session id"))?;
        let request_id = message.request_id.ok_or(MissingField("request id"))?;

        let proto = match message.args {
            Some(bytes) => prost::Message::decode(&bytes[..])?,
            None => Default::default(),
        };

        Ok(Request {
            name: name,
            session_id: session_id,
            request_id: request_id,
            data: R::from_proto(proto),
        })
    }
}

struct Response<R: action::Response> {
    session_id: String,
    request_id: Option<u64>,
    response_id: Option<u64>,
    data: R,
}

impl<R: action::Response> Response<R> {

    fn send(self) -> Result<()> {
        let message: rrg_proto::GrrMessage = self.try_into()?;

        let packet = Packet {
            service: String::from("GRR"),
            kind: Some(String::from("GrrMessage")),
            data: message,
        };

        use fleetspeak::WriteError::*;
        match fleetspeak::send(packet) {
            Ok(()) => Ok(()),
            Err(Encode(error)) => Err(error.into()),
            Err(Output(error)) => {
                // If we failed to deliver the message through Fleetspeak, it
                // means that our communication is broken (e.g. the pipe was
                // closed) and the agent should be killed.
                panic!("message delivery failure: {}", error)
            }
        }
    }
}

impl<R: action::Response> TryInto<rrg_proto::GrrMessage> for Response<R> {

    type Error = prost::EncodeError;

    fn try_into(self)
    -> std::result::Result<rrg_proto::GrrMessage, prost::EncodeError>
    {
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
