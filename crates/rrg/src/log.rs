// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

/// Initializes the logging submodule.
///
/// This function should be called only once at the beginning of the process
/// startup.
pub fn init(args: &crate::args::Args) {
    let mut logger = MultiLog::default();
    if args.log_to_stdout {
        logger.stdout_logger = Some(WriterLog::new(std::io::stdout()));
    }
    if let Some(ref path) = args.log_to_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("failed to open the log file");

        logger.file_logger = Some(WriterLog::new(file));
    }

    log::set_boxed_logger(Box::new(logger))
        .expect("failed to initialize logger");

    log::set_max_level(args.verbosity);
}

/// A wrapper for logging to multiple destinations.
struct MultiLog {
    /// Logger instance that writes messages to standard output.
    stdout_logger: Option<WriterLog<std::io::Stdout>>,
    /// Logger instance that writes messages to a file.
    file_logger: Option<WriterLog<std::fs::File>>,
}

impl MultiLog {

    /// Returns an iterator over all registered loggers.
    #[inline]
    fn loggers(&self) -> impl Iterator<Item = &dyn log::Log> {
        let stdout_logger_iter = self.stdout_logger
            .iter()
            .map(|logger| logger as &dyn log::Log);

        let file_logger_iter = self.file_logger
            .iter()
            .map(|logger| logger as &dyn log::Log);

        std::iter::empty()
            .chain(stdout_logger_iter)
            .chain(file_logger_iter)
    }
}

impl Default for MultiLog {

    fn default() -> MultiLog {
        MultiLog {
            stdout_logger: None,
            file_logger: None,
        }
    }
}

impl log::Log for MultiLog {

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.loggers().any(|logger| logger.enabled(metadata))
    }

    fn log(&self, record: &log::Record) {
        for logger in self.loggers() {
            logger.log(record);
        }
    }

    fn flush(&self) {
        for logger in self.loggers() {
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
