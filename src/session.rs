use std::fmt::{Display, Formatter};

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
    next_response_id: u64,
}

impl Session {

    pub fn known<S: Into<String>>(id: S) -> Session {
        Session {
            id: id.into(),
            next_response_id: 0,
        }
    }

    pub fn reply<R: Response>(&mut self, response: R) -> Result<()> {
        Message {
            session_id: self.id.clone(),
            response_id: self.next_response_id,
            data: response,
        }.send()?;

        self.next_response_id += 1;

        Ok(())
    }
}

struct Message<R: Response> {
    session_id: String,
    response_id: u64,
    data: R,
}

impl<R: Response> Message<R> {

    fn send(self) -> Result<()> {
        let mut data = Vec::new();
        prost::Message::encode(&self.data.into_proto(), &mut data)?;

        let proto = rrg_proto::GrrMessage {
            session_id: Some(self.session_id),
            response_id: Some(self.response_id),
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
