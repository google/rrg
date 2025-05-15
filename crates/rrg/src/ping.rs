// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO(@panhania): Remove once no longer needed.
/// Ping message sent periodically to the GRR server.
pub struct Ping {
    /// Time at which the message was (well, "is about to be") sent.
    pub sent: std::time::SystemTime,
    /// Increasing sequence number since the agent process was started.
    pub seq: u32,
}

impl crate::response::Item for Ping {

    type Proto = rrg_proto::ping::Ping;

    fn into_proto(self) -> rrg_proto::ping::Ping {
        let mut proto = rrg_proto::ping::Ping::new();
        proto.set_send_time(rrg_proto::into_timestamp(self.sent));
        proto.set_seq(self.seq);

        proto
    }
}
