// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the install date action.
//!
//! The install date action uses various heuristics to detect the operating
//! system install date.

use std::time::{SystemTime, Duration};

use log::error;
use crate::session::{self, Session};

/// A response type for the install date action.
struct Response {
    /// Install date of the operating system, or `None` if the attemps to
    /// obtain install date failed.
    time: Option<SystemTime>,
}

impl crate::response::Item for Response {

    type Proto = protobuf::well_known_types::UInt64Value;

    fn into_proto(self) -> Self::Proto {
        let time = match self.time {
            Some(time) => time,
            None => {
                error!("cannot get install date, all methods failed");
                std::time::UNIX_EPOCH
            },
        };
        let since_epoch = match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(err) => {
                error!(
                    "install date is {} seconds earlier than Unix epoch",
                    err.duration().as_secs()
                );
                Duration::from_secs(0)
            },
        };

        let mut proto = protobuf::well_known_types::UInt64Value::new();
        proto.set_value(since_epoch.as_secs());

        proto
    }
}

/// Handles requests for the install date action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    // TODO(@panhania): Original code from [`#36]` by alex65536@ had many good
    // heuristics that we should backport to `ospect::os::installed`.
    //
    // [`#36`]: https://github.com/google/rrg/pull/36
    session.reply(Response {
        time: ospect::os::installed().ok(),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_install_date() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);
        let time = response.time.unwrap();

        assert!(time <= SystemTime::now());
    }
}
