use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

use fleetspeak::Packet;

use crate::action::Response;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Send(fleetspeak::WriteError),
    Encode(prost::EncodeError),
}

impl Display for Error {

    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        use Error::*;

        match *self {
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
            Send(ref error) => Some(error),
            Encode(ref error) => Some(error),
        }
    }
}

impl From<fleetspeak::WriteError> for Error {

    fn from(error: fleetspeak::WriteError) -> Error {
        Error::Send(error)
    }
}

impl From<prost::EncodeError> for Error {

    fn from(error: prost::EncodeError) -> Error {
        Error::Encode(error)
    }
}

pub struct Session {
    id: String,
    request_id: u64,
    next_response_id: u64,
}

impl Session {

    pub fn reply<R: Response>(&mut self, response: R) -> Result<()> {
        Message {
            session_id: self.id.clone(),
            request_id: Some(self.request_id),
            response_id: Some(self.next_response_id),
            data: response,
        }.send()?;

        self.next_response_id += 1;

        Ok(())
    }
}

pub struct Sink<R: Response> {
    id: &'static str,
    kind: PhantomData<R>,
}

impl<R: Response> Sink<R> {

    pub fn send(&self, response: R) -> Result<()> {
        Message {
            session_id: String::from(self.id),
            request_id: None,
            response_id: None,
            data: response,
        }.send()
    }
}

pub static STARTUP: Sink<crate::action::startup::Response> = Sink {
    id: "/flows/F:Startup",
    kind: PhantomData,
};

struct Message<R: Response> {
    session_id: String,
    request_id: Option<u64>,
    response_id: Option<u64>,
    data: R,
}

impl<R: Response> Message<R> {

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
