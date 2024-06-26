/// Arguments of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
pub struct Args {
}

/// A result of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
struct Item {
}

/// Handles invocations of the `list_winreg_values` action.
#[cfg(target_family = "windows")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    todo!()
}

/// Handles invocations of the `list_winreg_values` action.
#[cfg(target_family = "unix")]
pub fn handle<S>(_: &mut S, _: ()) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Error, ErrorKind};
    Err(crate::session::Error::action(Error::from(ErrorKind::Unsupported)))
}

#[cfg(target_family = "windows")]
impl crate::request::Args for Args {

    type Proto = rrg_proto::get_winreg_value::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        todo!()
    }
}

#[cfg(target_family = "windows")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::get_winreg_value::Result;

    fn into_proto(self) -> Self::Proto {
        todo!()
    }
}
