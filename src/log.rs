use std::io::Write;

struct WriterLog<W: Write> {
    writer: std::sync::Mutex<W>,
}

impl<W: Write + Send + Sync> WriterLog<W> {

    fn new(writer: W) -> WriterLog<W> {
        WriterLog { writer: std::sync::Mutex::new(writer) }
    }
}

impl<W: Write + Send + Sync> log::Log for WriterLog<W> {

    // TODO: Add support for log filtering. For now we just output everything as
    // there is no way to change the log verbosity.

    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let now = std::time::SystemTime::now();

        // We consider failures to write to the log stream critical. Otherwise,
        // if there is some other issue with the system it is not possible to
        // properly communicate it. Thus, we panic on all write errors.
        let mut writer = self.writer.lock()
            .expect("failed to acquire log output stream lock");

        || -> Result<(), std::io::Error> {
            write! {
                writer,
                "[{level} {timestamp} ",
                level = record.level(),
                timestamp = humantime::format_rfc3339_nanos(now)
            }?;
            match record.file() {
                Some(file) => write!(writer, "{file}")?,
                None => write!(writer, "<unknown>")?,
            }
            match record.line() {
                Some(line) => write!(writer, ":{line}]")?,
                None => write!(writer, ":<unknown>]")?,
            }

            write!(writer, " {}\n", record.args())?;

            Ok(())
        }().expect("failed to write to the log output stream")
    }

    fn flush(&self) {
        // Similarly to write errors, we also panic on flush errors as there is
        // nothing we can do otherwise.
        self.writer
            .lock()
            .expect("failed to acquire log output stream lock")
            .flush()
            .expect("failed to flush the log output stream");
    }
}

pub fn init(verbosity: log::LevelFilter) {
    use lazy_static::lazy_static;

    lazy_static! {
        static ref LOGGER: WriterLog<std::io::Stdout> = {
            WriterLog::new(std::io::stdout())
        };
    }

    log::set_logger(&*LOGGER)
        .expect("failed to initialize logger");

    log::set_max_level(verbosity);
}
