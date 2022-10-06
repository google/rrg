/// An action request message.
pub struct Request {
    /// A unique id of the request.
    id: RequestId,
    /// A name of the action to execute.
    action: String,
    /// Serialized Protocol Buffers message with request arguments.
    serialized_args: Option<Vec<u8>>,
}

/// A unique identifier of a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RequestId {
    /// A server-issued session identifier (usually corresponds to a flow).
    session_id: String,
    /// A server-issued request identifier.
    request_id: u64,
}

impl Request {

    /// Parses the action arguments stored in this request.
    ///
    /// At the moment the request is received we don't know yet what is the type
    /// of the arguments it contains and so we cannot interpret it. Once the
    /// request is dispatched to an appropriate action handler, we can parse the
    /// arguments to a concrete type.
    pub fn parse_args<A>(&self) -> Result<A, crate::action::ParseArgsError>
    where
        A: crate::action::Args,
    {
        let proto_args = match &self.serialized_args {
            Some(ref bytes) => protobuf::Message::parse_from_bytes(bytes)?,
            None => Default::default(),
        };

        A::from_proto(proto_args)
    }
}
