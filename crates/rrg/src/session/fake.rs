use std::any::Any;

use crate::Sink;

/// A session implementation intended to be used in tests.
///
/// Testing actions with normal session objects can be quite hard, since
/// they communicate with the outside world (through Fleetspeak). Since we
/// want to keep the tests minimal and not waste resources on unneeded I/O,
/// using real sessions is not an option.
///
/// Instead, one can use a `Fake` session. It simply accumulates responses
/// that the action sends and lets the creator inspect them later.
pub struct FakeSession {
    replies: Vec<Box<dyn Any>>,
    parcels: std::collections::HashMap<Sink, Vec<Box<dyn Any>>>,
}

impl FakeSession {

    /// Constructs a new fake session.
    pub fn new() -> FakeSession {
        FakeSession {
            replies: Vec::new(),
            parcels: std::collections::HashMap::new(),
        }
    }

    /// Yields the number of replies that this session sent so far.
    pub fn reply_count(&self) -> usize {
        self.replies.len()
    }

    /// Retrieves a reply corresponding to the given id.
    ///
    /// The identifier corresponding to the first response is 0, the second one
    /// is 1 and so on.
    ///
    /// This method will panic if a reply with the specified `id` does not exist
    /// or if it exists but has a wrong type.
    pub fn reply<R>(&self, id: usize) -> &R
    where
        R: crate::action::Item + 'static,
    {
        match self.replies().nth(id) {
            Some(reply) => reply,
            None => panic!("no reply #{}", id),
        }
    }

    /// Constructs an iterator over session replies.
    ///
    /// The iterator will panic (but not immediately) if some reply has an
    /// incorrect type.
    pub fn replies<R>(&self) -> impl Iterator<Item = &R>
    where
        R: crate::action::Item + 'static
    {
        self.replies.iter().map(|reply| {
            reply.downcast_ref().expect("unexpected reply type")
        })
    }

    /// Yields the number of parcels sent so far to the specified sink.
    pub fn parcel_count(&self, sink: Sink) -> usize {
        match self.parcels.get(&sink) {
            Some(parcels) => parcels.len(),
            None => 0,
        }
    }

    /// Retrieves a parcel with the given id sent to a particular sink.
    ///
    /// The identifier corresponding to the first parcel to the particular sink
    /// is 0, to the second one (to the same sink) is 1 and so on.
    ///
    /// This method will panic if a reply with the specified `id` to the given
    /// `sink` does not exist or if it exists but has wrong type.
    pub fn parcel<I>(&self, sink: Sink, id: usize) -> &I
    where
        I: crate::action::Item + 'static,
    {
        match self.parcels(sink).nth(id) {
            Some(parcel) => parcel,
            None => panic!("no parcel #{} for sink '{:?}'", id, sink),
        }
    }

    /// Constructs an iterator over session parcels for the given sink.
    ///
    /// The iterator will panic (but not immediately) if some parcels have an
    /// incorrect type.
    pub fn parcels<I>(&self, sink: Sink) -> impl Iterator<Item = &I>
    where
        I: crate::action::Item + 'static,
    {
        // Since the empty iterator (as defined in the standard library) is a
        // specific type, it cannot be returned in one branch but not in another
        // branch.
        //
        // Instead, we use the fact that `Option` is an iterator and then we
        // squash it with `Iterator::flatten`.
        let parcels = self.parcels.get(&sink).into_iter().flatten();

        parcels.map(move |parcel| match parcel.downcast_ref() {
            Some(parcel) => parcel,
            None => panic!("unexpected parcel type in sink '{:?}'", sink),
        })
    }
}

impl crate::session::Session for FakeSession {

    fn reply<I>(&mut self, item: I) -> crate::session::Result<()>
    where
        I: crate::action::Item + 'static,
    {
        self.replies.push(Box::new(item));

        Ok(())
    }

    fn send<I>(&mut self, sink: Sink, item: I) -> crate::session::Result<()>
    where
        I: crate::action::Item + 'static,
    {
        let parcels = self.parcels.entry(sink).or_insert_with(Vec::new);
        parcels.push(Box::new(item));

        Ok(())
    }
}
