// TODO: Rename this module to `message` (and deprecte the old one).
// TODO: Write top-level documentation for this module (and its submodules).

mod request;
mod response;

pub use request::{Request, RequestId};
pub use response::{Item, Status, ResponseBuilder, ResponseId};

// TODO(@panhania): Unexpose once `message` and `comms` are merged into one.
pub use request::{ReceiveRequestError};
