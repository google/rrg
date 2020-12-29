use std::fs::File;
use std::path::{Path, PathBuf};

use rrg::session::Sink;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "timeline", about = "A binary for the timeline action.")]
struct Opts {
    #[structopt(long="root", name="FILE", default_value="/",
                help="A path to the root directory to timeline.")]
    root: PathBuf,

    #[structopt(long="output", about="FILE",
                help="A path to a file to dump the results into.")]
    output: PathBuf,
}

struct Session {
    output: File,
}

impl Session {

    fn open<P: AsRef<Path>>(output: P) -> Session {
        let output = File::create(output)
            .expect("failed to create the output file");

        Session {
            output: output,
        }
    }
}

impl rrg::session::Session for Session {

    fn reply<R>(&mut self, response: R) -> rrg::session::Result<()>
    where
        R: rrg::action::Response + 'static,
    {
        // We don't care about the chunk ids.
        drop(response);
        Ok(())
    }

    fn send<R>(&mut self, sink: Sink, response: R) -> rrg::session::Result<()>
    where
        R: rrg::action::Response + 'static,
    {
        use std::io::Write as _;
        use byteorder::{BigEndian, WriteBytesExt as _};

        assert_eq!(sink, Sink::TRANSFER_STORE);

        let response = (&response as &dyn std::any::Any)
            .downcast_ref::<rrg::action::timeline::Chunk>()
            .expect("unexpected response type");

        self.output.write_u64::<BigEndian>(response.data.len() as u64)
            .expect("failed to write chunk size tag");
        self.output.write_all(&response.data[..])
            .expect("failed to write chunk data");

        Ok(())
    }
}

fn main() {
    let opts = Opts::from_args();

    let mut session = Session::open(opts.output);

    let request = rrg::action::timeline::Request {
        root: opts.root,
    };

    rrg::action::timeline::handle(&mut session, request)
        .expect("failed to execute the action");
}
