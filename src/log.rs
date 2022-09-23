/// Initializes the logging submodule.
///
/// This function should be called only once at the beginning of the process
/// startup.
pub fn init(args: &crate::args::Args) {
    let mut logger = MultiLog::new();
    if args.log_to_stdout {
        logger.push(WriterLog::new(std::io::stdout()));
    }
    if let Some(ref path) = args.log_to_file {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("failed to open the log file");

        logger.push(WriterLog::new(file));
    }

    log::set_boxed_logger(Box::new(logger))
        .expect("failed to initialize logger");

    log::set_max_level(args.verbosity);
}

/// A wrapper for logging to multiple destinations.
struct MultiLog {
    /// A list of all registered loggers.
    loggers: Vec<Box<dyn log::Log>>,
}

impl MultiLog {

    /// Creates a new wrapper with no registered loggers.
    fn new() -> MultiLog {
        MultiLog {
            loggers: Vec::new(),
        }
    }

    /// Registers a new destination to log to.
    fn push<L: log::Log + 'static>(&mut self, logger: L) {
        self.loggers.push(Box::new(logger));
    }
}

impl log::Log for MultiLog {

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.loggers.iter().any(|logger| logger.enabled(metadata))
    }

    fn log(&self, record: &log::Record) {
        for log in &self.loggers {
            log.log(record);
        }
    }

    fn flush(&self) {
        for logger in &self.loggers {
            logger.flush();
        }
    }
}

/// A simple logger implementation for logging to writable streams (e.g. files).
struct WriterLog<W: std::io::Write + Send + Sync> {
    writer: std::sync::Mutex<W>,
}

impl<W: std::io::Write + Send + Sync> WriterLog<W> {

    /// Create a new logger for the given writable stream.
    fn new(writer: W) -> WriterLog<W> {
        WriterLog { writer: std::sync::Mutex::new(writer) }
    }
}

impl<W: std::io::Write + Send + Sync> log::Log for WriterLog<W> {

    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

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
