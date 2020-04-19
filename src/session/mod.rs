mod error;

use fleetspeak::Packet;

use crate::action::Response;
pub use self::error::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub trait Session {
    fn send<R: Response>(&mut self, response: R) -> Result<()>;
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

    fn send<R: Response>(&mut self, response: R) -> Result<()> {
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

pub struct Sink {
    id: &'static str,
}

impl Session for Sink {

    fn send<R: Response>(&mut self, response: R) -> Result<()> {
        Message {
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
