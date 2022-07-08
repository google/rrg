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

        print!("[");
        print! {
            "{level} {timestamp} ",
            level = record.level(),
            timestamp = humantime::format_rfc3339_nanos(now)
        };

        match record.file() {
            Some(file) => print!("{file}"),
            None => print!("<unknown>"),
        }

        match record.line() {
            Some(line) => print!(":{line}"),
            None => print!(":<unknown>"),
        }

        print!("{}", record.args());
        print!("]");

        println!();
    }

    fn flush(&self) {
        // There is nothing we can do in case of a flushing error, so we just
        // ignore it.
        let _ = std::io::stdout().flush();
    }
}
