// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub mod startup;

// TODO: Have a more specific error type.
type Error = Box<dyn std::error::Error>;

pub trait Request {
    type Proto: prost::Message;
    fn from_proto(proto: Self::Proto) -> Self;
}

pub trait Response {
    const RDF_NAME: Option<&'static str>;
    type Proto: prost::Message;
    fn into_proto(self) -> Self::Proto;
}
