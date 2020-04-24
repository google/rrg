mod error;

use std::convert::{TryFrom, TryInto};

use fleetspeak::Packet;
use log::error;

use crate::action;
pub use self::error::{Error, ParseError};

pub type Result<T> = std::result::Result<T, Error>;

pub fn execute<S, R, H>(session: &mut S, handler: H, payload: Payload) -> Result<()>
where
    S: Session,
    R: action::Request,
    H: FnOnce(&mut S, R) -> Result<()>,
{
    handler(session, payload.parse()?)
}

pub fn handle<M>(message: M)
where
    M: TryInto<Demand, Error=ParseError>,
{
    let demand = match message.try_into() {
        Ok(demand) => demand,
        Err(error) => {
            error!("failed to parse the message: {}", error);
            return;
        }
    };

    let mut session = Action::new(demand.header.clone());
    let result = action::dispatch(&demand.action, &mut session, demand.payload);

    let status = Status {
        header: demand.header,
        result: result,
    };

    let message = match status.try_into() {
        Ok(message) => message,
        Err(error) => {
            // If we cannot encode the final status message, there is nothing
            // we can do to notify the server, as status is responsible for
            // reporting errors. We can only log the error and carry on.
            error!("failed to encode status message: {}", error);
            return;
        }
    };

    send(message);
}

pub trait Session {
    fn send<R: action::Response>(&mut self, response: R) -> Result<()>;
}

pub struct Action {
    header: Header,
    next_response_id: u64,
}

impl Action {

    pub fn new(header: Header) -> Action {
        Action {
            header: header,
            next_response_id: 0,
        }
    }
}

impl Session for Action {

    fn send<R: action::Response>(&mut self, response: R) -> Result<()> {
        Response {
            session_id: self.header.session_id.clone(),
            request_id: Some(self.header.request_id),
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

pub struct Demand {
    pub action: String,
    pub header: Header,
    pub payload: Payload,
}

impl TryFrom<rrg_proto::GrrMessage> for Demand {

    type Error = ParseError;

    fn try_from(message: rrg_proto::GrrMessage)
    -> std::result::Result<Demand, ParseError>
    {
        use ParseError::*;

        let header = Header {
            session_id: message.session_id.ok_or(MissingField("session id"))?,
            request_id: message.request_id.ok_or(MissingField("request id"))?,
        };

        Ok(Demand {
            action: message.name.ok_or(MissingField("action name"))?,
            header: header,
            payload: Payload(message.args),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub session_id: String,
    pub request_id: u64,
}

#[derive(Debug)]
pub struct Payload(Option<Vec<u8>>);

impl Payload {

    pub fn parse<R>(&self) -> std::result::Result<R, ParseError>
    where
        R: action::Request,
    {
        let proto = match self {
            Payload(Some(bytes)) => prost::Message::decode(&bytes[..])?,
            Payload(None) => Default::default(),
        };

        Ok(R::from_proto(proto))
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
        let message = self.try_into()?;
        send(message);

        Ok(())
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

struct Status {
    header: Header,
    result: Result<()>,
}

impl TryInto<rrg_proto::GrrMessage> for Status {

    type Error = prost::EncodeError;

    fn try_into(self)
    -> std::result::Result<rrg_proto::GrrMessage, prost::EncodeError> {
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
            session_id: Some(self.header.session_id),
            response_id: Some(self.header.request_id),
            r#type: Some(rrg_proto::grr_message::Type::Status.into()),
            args_rdf_name: Some(String::from("GrrStatus")),
            args: Some(data),
            ..Default::default()
        })
    }
}

fn send(message: rrg_proto::GrrMessage) {
        let packet = Packet {
            service: String::from("GRR"),
            kind: Some(String::from("GrrMessage")),
            data: message,
        };

        if let Err(error) = fleetspeak::send(packet) {
            // If we failed to deliver the message through Fleetspeak, it means
            // that our communication is broken (e.g. the pipe was closed) and
            // the agent should be killed.
            panic!("message delivery failure: {}", error)
        };
}
