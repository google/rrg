mod error;

use std::convert::{TryFrom, TryInto};

use fleetspeak::Packet;

use crate::action;
pub use self::error::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub type Handler<R> = fn(&mut Action, R) -> Result<()>;

pub fn handle<R, M>(handler: Handler<R>, message: M) -> Result<()>
where
    R: action::Request,
    M: TryInto<Request<R>, Error=Box<dyn std::error::Error>>,
{
    let request = message.try_into().unwrap(); // TODO: Proper error handling.

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

    type Error = Box<dyn std::error::Error>; // TODO: More specific error type.

    fn try_from(message: rrg_proto::GrrMessage)
    -> std::result::Result<Request<R>, Box<dyn std::error::Error>>
    {
        let name = match message.name {
            Some(name) => name,
            None => Err(String::from("request without an action name"))?,
        };

        let session_id = match message.session_id {
            Some(session_id) => session_id,
            None => Err(String::from("request without session id"))?,
        };

        let request_id = match message.request_id {
            Some(request_id) => request_id,
            None => Err(String::from("request without request id"))?,
        };

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
        let mut data = Vec::new();
        prost::Message::encode(&self.data.into_proto(), &mut data)?;

        let proto = rrg_proto::GrrMessage {
            session_id: Some(self.session_id),
            response_id: self.response_id,
            request_id: self.request_id,
            r#type: Some(rrg_proto::grr_message::Type::Message.into()),
            args_rdf_name: R::RDF_NAME.map(String::from),
            args: Some(data),
            ..Default::default()
        };

        fleetspeak::send(Packet {
            service: String::from("GRR"),
            kind: Some(String::from("GrrMessage")),
            data: proto,
        })?;

        Ok(())
    }
}
