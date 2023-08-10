// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use log::Log;
use lazy_static::lazy_static;

/// Initializes the logging submodule.
///
/// This function should be called only once at the beginning of the process
/// startup.
pub fn init(args: &crate::args::Args) {
    let mut logger = Logger::default();
    if args.log_to_stdout {
        let stdout = std::io::stdout();
        logger.stdout_logger = Some(WriterLogger::new(stdout, args.verbosity));
    }
    if let Some(ref path) = args.log_to_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("failed to open the log file");

        logger.file_logger = Some(WriterLogger::new(file, args.verbosity));
    }

    log::set_boxed_logger(Box::new(logger))
        .expect("failed to initialize logger");

    // Note that individual loggers have their own logging levels:
    //
    //   * The standard output logger and file loggers use `args.verbosity`.
    //   * The response logger uses the level specified in the request.
    //
    // If we were to set the global max level to `args.verbosity` it would make
    // it impossible to send to the server logs with lower level even if the
    // request mandates it. This is why we initialize it to `Trace` (which is
    // the maximum available level).
    log::set_max_level(log::LevelFilter::Trace);
}

/// [`Log`] implementation that aggregates all supported loggers.
struct Logger {
    /// Logger instance that writes messages to standard output.
    stdout_logger: Option<WriterLogger<std::io::Stdout>>,
    /// Logger instance that writes messages to a file.
    file_logger: Option<WriterLogger<std::fs::File>>,
    /// Logger instance that sends messages to the GRR server.
    response_logger: GlobalResponseLogger,
}

impl Logger {

    /// Returns an iterator over all registered loggers.
    #[inline]
    fn loggers(&self) -> impl Iterator<Item = &dyn Log> {
        let stdout_logger_iter = self.stdout_logger
            .iter()
            .map(|logger| logger as &dyn Log);

        let file_logger_iter = self.file_logger
            .iter()
            .map(|logger| logger as &dyn Log);

        let response_logger_iter = {
            std::iter::once(&self.response_logger as &dyn Log)
        };

        std::iter::empty()
            .chain(stdout_logger_iter)
            .chain(file_logger_iter)
            .chain(response_logger_iter)
    }
}

impl Default for Logger {

    fn default() -> Logger {
        Logger {
            stdout_logger: None,
            file_logger: None,
            response_logger: GlobalResponseLogger,
        }
    }
}

impl Log for Logger {

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

/// [`Log`] implementation for logging to writable streams (e.g. files).
struct WriterLogger<W: std::io::Write + Send + Sync> {
    /// Stream to write the log messages to.
    writer: std::sync::Mutex<W>,
    /// Minimum level at which messages are written to the stream.
    log_level: log::LevelFilter,
}

impl<W: std::io::Write + Send + Sync> WriterLogger<W> {

    /// Create a new logger for the given writable stream.
    fn new(writer: W, log_level: log::LevelFilter) -> WriterLogger<W> {
        WriterLogger {
            writer: std::sync::Mutex::new(writer),
            log_level,
        }
    }
}

impl<W: std::io::Write + Send + Sync> Log for WriterLogger<W> {

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.log_level
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

lazy_static! {
    /// A global instance of a logger that sends messages to the GRR server.
    ///
    /// This instance is `None` normally and is set to `Some` only when we are
    /// processing a request. To set the logger instance one should use the
    /// [`ResponseLog::context`] method.
    static ref RESPONSE_LOGGER: std::sync::RwLock<Option<ResponseLogger>> = {
        std::sync::RwLock::new(None)
    };
}


/// [`Log`] implementation that uses global instance of [`ResponseLogger`].
struct GlobalResponseLogger;

impl Log for GlobalResponseLogger {

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let logger = RESPONSE_LOGGER.read()
            .expect("failed to acquire response logger lock");

        match logger.as_ref() {
            Some(logger) => logger.enabled(metadata),
            None => false,
        }
    }

    fn log(&self, record: &log::Record) {
        let logger = RESPONSE_LOGGER.read()
            .expect("failed to acquire response logger lock");

        match logger.as_ref() {
            Some(logger) => logger.log(record),
            None => (),
        }
    }

    fn flush(&self) {
        let logger = RESPONSE_LOGGER.read()
            .expect("failed to acquire reponse logger lock");

        match logger.as_ref() {
            Some(logger) => logger.flush(),
            None => (),
        }
    }
}

/// [`Log`] implementation that sends logs to the GRR server.
pub struct ResponseLogger {
    /// Builder used to construct [`crate::response::Log`] objects.
    log_builder: crate::LogBuilder,
    /// Minimum level at which messages are sent to the server.
    log_level: log::LevelFilter,
}

impl ResponseLogger {

    /// Constructs a new logger instance for the given [`crate::Request`].
    pub fn new(request: &crate::Request) -> ResponseLogger {
        ResponseLogger {
            log_builder: crate::LogBuilder::new(request.id()),
            log_level: request.log_level(),
        }
    }

    /// Runs the specified function in a context with this logger enabled.
    ///
    /// # Panics
    ///
    /// This function might panic or deadlock if called on a thread already
    /// running within a response logger context.
    pub fn context<F, T>(self, func: F) -> T
    where
        F: FnOnce() -> T,
    {
        let mut logger = RESPONSE_LOGGER.write()
            .expect("failed to acquire response logger lock");

        *logger = Some(self);
        let result = func();
        *logger = None;

        result
    }
}

impl Log for ResponseLogger {

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let log = self.log_builder.log(record);
        log.send_unaccounted();
    }

    fn flush(&self) {
    }
}
