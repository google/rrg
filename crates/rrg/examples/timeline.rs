//! An example that timelines the specified folder.
//!
//! The timeline action is one of the filesystem tools that the GRR agent
//! exposes. Its description is pretty simple: given a folder, it returns a
//! stream of stat entries for all the files in it (including all subfolders).
//!
//! This example is a tiny wrapper around this action that allows to execute it
//! as a standalone binary without all the RRG setup required. A primary reason
//! for its existence is to compare the efficiency Rust implementation against
//! the existing Python one.

use std::fs::File;
use std::path::{Path, PathBuf};

use rrg::action::deprecated::timeline;

/// A binary for the timeline action.
#[derive(argh::FromArgs)]
struct Args {
    /// A path to the root directory to timeline.
    #[argh(option,
           long = "root",
           arg_name = "FILE",
           default = "::std::path::PathBuf::from(\"/\")",
           description = "root directory to timeline")]
    root: PathBuf,

    /// A path to a file to dump the results into.
    #[argh(positional,
           arg_name = "OUTPUT",
           description = "path to dump the results into")]
    output: PathBuf,
}

/// A session type of the timeline example.
///
/// Every action handler needs a session object. "Real" sessions handle comms
/// with the GRR server, error reporting and alike. However, this is not needed
/// here and the example session simply dumps everything into the specified file
/// encoding data in the gzchunked format.
struct Session {
    /// A file into which the data chunks of the output are dumped.
    output: File,
}

impl Session {

    /// Creates a session object that will write to the given `output` path.
    fn open<P: AsRef<Path>>(output: P) -> Session {
        let output = File::create(output)
            .expect("failed to create the output file");

        Session {
            output: output,
        }
    }
}

impl rrg::session::Session for Session {

    fn reply<I>(&mut self, item: I) -> rrg::session::Result<()>
    where
        I: rrg::response::Item + 'static,
    {
        // For now we are not interested in doing anything useful with chunk ids
        // since everything is dumped into one file and there is no need to
        // refer to a particular chunk.
        //
        // In the future they might be useful for printing some statistics about
        // the collected files.
        drop(item);

        Ok(())
    }

    fn send<I>(&mut self, sink: rrg::Sink, item: I) -> rrg::session::Result<()>
    where
        I: rrg::response::Item + 'static,
    {
        use std::io::Write as _;
        use byteorder::{BigEndian, WriteBytesExt as _};

        // Just a sanity check in case the implementation of the timeline action
        // starts sending data to other sinks.
        assert_eq!(sink, rrg::Sink::Blob);

        let parcel = (&item as &dyn std::any::Any)
            .downcast_ref::<timeline::Chunk>()
            .expect("unexpected response type");

        self.output.write_u64::<BigEndian>(parcel.data.len() as u64)
            .expect("failed to write chunk size tag");
        self.output.write_all(&parcel.data[..])
            .expect("failed to write chunk data");

        Ok(())
    }
}

fn main() {
    let args: Args = argh::from_env();

    timeline::handle(&mut Session::open(args.output), timeline::Request {
        root: args.root,
    }).expect("failed to execute the action");
}
