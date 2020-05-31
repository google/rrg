use std::fs;
use std::time::{SystemTime, Duration};

use log::error;
use crate::session::{self, Session};

struct Response {
    time: Option<SystemTime>,
}

impl super::Response for Response {

    // TODO : change to RDFDatetime when the client will be capable to send
    // "raw" strings without wrapping them into protobuf
    const RDF_NAME: Option<&'static str> = Some("DataBlob");

    type Proto = u64;

    fn into_proto(self) -> Self::Proto {
        let time = match self.time {
            Some(time) => time,
            None => {
                error!("cannot get install time, all methods failed");
                std::time::UNIX_EPOCH
            },
        };
        let since_epoch = match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(err) => {
                error!(
                    "install date is {} seconds earlier than Unix epoch",
                    err.duration().as_secs()
                );
                Duration::from_secs(0)
            },
        };
        since_epoch.as_secs()
    }
}

#[cfg(target_os = "linux")]
fn get_install_time() -> Option<SystemTime> {
    // First, check the creation time of the root. This method works on
    // Linux >= 4.11.
    let time = fs::metadata("/").and_then(|metadata| metadata.created());
    if let Ok(time) = time {
        return Some(time);
    }

    // TODO : parse dumpe2fs

    // Then, search for various files that were potentially modified only
    // on installation:
    // * /var/log/installer/: This works well on Debian-based systems, if the
    //   installation logs were not purged.
    // * /root/install.log: The location of installation logs for RHEL-based
    //   distributions.
    // * /etc/hostname: In most cases, we may assume that the hostname didn't
    //   change after installation.
    // * /lost+found: This method was used by Python version on GRR client, so
    //   leaving it here.
    static CANDIDATES: [&str; 5] = [
        "/var/log/installer/syslog",
        "/var/log/installer/status",
        "/root/install.log",
        "/etc/hostname",
        "/lost+found",
    ];
    for path in &CANDIDATES {
        let time = fs::metadata(path).and_then(|metadata| metadata.modified());
        if let Ok(time) = time {
            return Some(time);
        }
    }

    // We tried our best and all the methods have failed, so just give up.
    None
}

// TODO : add other ways for GNU/Linux
// TODO : add OS X and Windows

pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    session.reply(Response {time: get_install_time()})?;
    Ok(())
}

// TODO: write docs
// TODO: add tests

#[cfg(test)]
mod tests {

    use super::*;
    use humantime::Timestamp;

    #[test]
    fn test_installation_date() {
        let mut session = session::test::Fake::new();
        assert!(handle(&mut session, ()).is_ok());
        assert_eq!(session.reply_count(), 1);
        let response: &Response = session.reply(0);
        let time = response.time.unwrap();

        // We assume here that the tests won't be run for very old systems
        // installed before 01.01.2000.
        let lower_limit: Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();
        let lower_limit: SystemTime = lower_limit.into();
        // The upper limit for the installation is the current time.
        let upper_limit = SystemTime::now();

        assert!(time >= lower_limit);
        assert!(time <= upper_limit);
    }
}
