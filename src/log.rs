use std::io::Write;

struct StdoutLog;

impl log::Log for StdoutLog {

    // TODO: Add support for log filtering. For now we just output everything as
    // there is no way to change the log verbosity.

    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let now = std::time::SystemTime::now();

        print! {
            "[{level} {timestamp} ",
            level = record.level(),
            timestamp = humantime::format_rfc3339_nanos(now)
        };
        match record.file() {
            Some(file) => print!("{file}"),
            None => print!("<unknown>"),
        }
        match record.line() {
            Some(line) => print!(":{line}]"),
            None => print!(":<unknown>]"),
        }

        println!(" {}", record.args());
    }

    fn flush(&self) {
        // There is nothing we can do in case of a flushing error, so we just
        // ignore it.
        let _ = std::io::stdout().flush();
    }
}

pub fn init() {
    static LOGGER: StdoutLog = StdoutLog;

    log::set_logger(&LOGGER)
        .expect("failed to initialize logger");

    log::set_max_level(log::STATIC_MAX_LEVEL);
}
