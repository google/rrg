// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use crate::action;
use crate::session;

pub const STARTUP: Sink = Sink { id: "/flows/F:Startup" };

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sink {
    id: &'static str,
}

impl Sink {

    pub fn wrap<R>(&self, response: R) -> session::Response<R>
    where
        R: action::Response,
    {
        session::Response {
            session_id: String::from(self.id),
            request_id: None,
            response_id: None,
            data: response,
        }
    }
}
