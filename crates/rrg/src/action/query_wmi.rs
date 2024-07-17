// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Arguments of the `query_wmi` action.
#[cfg(target_family = "windows")]
pub struct Args {
    /// WQL query [1] to run.
    ///
    /// [1]: https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi
    query: std::ffi::OsString,
}

/// A result of the `query_wmi` action.
#[cfg(target_family = "windows")]
struct Item {
    /// Single row of the query result.
    row: wmi::QueryRow,
}

/// Handles invocations of the `query_wmi` action.
#[cfg(target_family = "windows")]
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let query = wmi::query(&args.query)
        .map_err(crate::session::Error::action)?;

    let rows = query.rows()
        .map_err(crate::session::Error::action)?;

    // Depending on the implementation, sometimes even if the query is invalid,
    // we get an error from the system only after we poll for the first row (but
    // sometimes we get it immediately, e.g. when running under Wine).
    //
    // We also do not want to fail the entire action if only some of the rows
    // failed to be fetched. Thus, we want to model the behaviour where we fail
    // the entire action if there are no rows at all but we do not do it if
    // there are any rows to be returned.
    //
    // We introduce auxiliary `Status` struct encoding a state machine that
    // implements such logic.
    enum Status {
        /// There were no rows at all.
        None,
        /// There were some rows returned.
        Some,
        /// There were only errors reported.
        Error(std::io::Error),
    }

    let mut status: Status = Status::None;

    for row in rows {
        let row = match row {
            Ok(row) => row,
            Err(error) => {
                log::error!("failed to obtain WMI query row: {}", error);
                // If there were no rows at all so far we keep the error in case
                // there are not going to be any further. We only keep the first
                // error—this is a rather arbitrary choice as all errors will be
                // logged anyway but might offer better experience when handling
                // these on the GRR flow level.
                if matches!(status, Status::None) {
                    status = Status::Error(error);
                }
                continue;
            }
        };

        session.reply(Item { row })?;
        // We reported a row, so we unconditionally change the status. Even if
        // there was an error, we will not fail the action at this point.
        status = Status::Some;
    }

    // As mentioned, we succeed the action if there were any rows reported or
    // if there was nothing at all. However, if there were only errors, we fail
    // it with the first error that occurred.
    match status {
        Status::None | Status::Some => Ok(()),
        Status::Error(error) => Err(crate::session::Error::action(error)),
    }
}

/// Handles invocations of the `query_wmi` action.
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

    type Proto = rrg_proto::query_wmi::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        Ok(Args {
            query: std::ffi::OsString::from(proto.take_query()),
        })
    }
}

#[cfg(target_family = "windows")]
impl crate::response::Item for Item {

    type Proto = rrg_proto::query_wmi::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::query_wmi::Result::new();

        for (name, value) in self.row {
            let proto_name = name.to_string_lossy().into_owned();
            let mut proto_value = rrg_proto::query_wmi::Value::new();

            match value {
                wmi::QueryValue::None => (),
                wmi::QueryValue::Bool(bool) => {
                    proto_value.set_bool(bool)
                }
                wmi::QueryValue::U8(u8) => {
                    proto_value.set_uint(u64::from(u8))
                }
                wmi::QueryValue::I8(i8) => {
                    proto_value.set_int(i64::from(i8))
                }
                wmi::QueryValue::U16(u16) => {
                    proto_value.set_uint(u64::from(u16))
                }
                wmi::QueryValue::I16(i16) => {
                    proto_value.set_int(i64::from(i16))
                }
                wmi::QueryValue::U32(u32) => {
                    proto_value.set_uint(u64::from(u32))
                }
                wmi::QueryValue::I32(i32) => {
                    proto_value.set_int(i64::from(i32))
                }
                wmi::QueryValue::U64(u64) => {
                    proto_value.set_uint(u64)
                }
                wmi::QueryValue::I64(i64) => {
                    proto_value.set_int(i64)
                }
                wmi::QueryValue::F32(f32) => {
                    proto_value.set_float(f32)
                }
                wmi::QueryValue::F64(f64) => {
                    proto_value.set_double(f64)
                }
                wmi::QueryValue::String(string) => {
                    proto_value.set_string(string.to_string_lossy().into_owned())
                }
                wmi::QueryValue::Unsupported(_) => (),
            }

            proto.mut_row().insert(proto_name, proto_value);
        }

        proto
    }
}

#[cfg(test)]
#[cfg(target_family = "windows")]
mod tests {

    use super::*;

    #[test]
    fn handle_invalid_query() {
        let args = Args {
            query: "
                INSERT
                INTO
                  Win32_OperatingSystem (Name, Version)
                VALUES
                  ('Foo', '1.3.3.7')
            ".into(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());

    }

    #[test]
    fn handle_no_rows() {
        let args = Args {
            query: "
                SELECT
                  *
                FROM
                  Win32_OperatingSystem
                WHERE
                  FreePhysicalMemory < 0
            ".into(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());
        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn handle_some_rows() {
        let args = Args {
            query: "
                SELECT
                  *
                FROM
                  Win32_OperatingSystem
                WHERE
                  FreePhysicalMemory >= 0
            ".into(),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_ok());
        assert_eq!(session.reply_count(), 1);
    }
}
