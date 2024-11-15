// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::path::PathBuf;

/// Arguments of the `grep_file_contents` action.
pub struct Args {
    /// Path to the file to grep the contents of.
    path: PathBuf,
    /// Regular expression to search for in the file contents.
    regex: regex::Regex,
}

/// Result of the `grep_file_contents` action.
pub struct Item {
    /// Byte offset within the file from which the content matched.
    offset: u64,
    /// Content that matched the specified regular expression.
    content: String,
}

/// Handles invocations of the `grep_file_contents` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    let file = std::fs::File::open(&args.path)
        .map_err(crate::session::Error::action)?;

    let mut file = crate::io::LineReader::new(file)
        // We want to support lines only up to 1 MiB. Fleetspeak does not allow
        // for messages bigger than 2 MiB anyway.
        .with_max_line_len(1 * 1024 * 1024);

    let mut line = String::new();
    let mut offset = 0;

    loop {
        line.clear();
        let len = match file.read_line_lossy(&mut line) {
            Ok(0) => return Ok(()),
            Ok(len) => len,
            Err(error) => return Err(crate::session::Error::action(error)),
        };

        for matcz in args.regex.find_iter(&line) {
            session.reply(Item {
                offset: offset + matcz.start() as u64,
                content: matcz.as_str().to_string(),
            })?;
        }

        offset += len as u64;
    }
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::grep_file_contents::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let path = PathBuf::try_from(proto.take_path())
            .map_err(|error| ParseArgsError::invalid_field("path", error))?;

        let regex = regex::Regex::new(proto.regex())
            .map_err(|error| ParseArgsError::invalid_field("regex", error))?;

        Ok(Args {
            path,
            regex,
        })
    }
}

impl crate::response::Item for Item {

    type Proto = rrg_proto::grep_file_contents::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = Self::Proto::default();
        proto.set_offset(self.offset);
        proto.set_content(self.content);

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn handle_empty_file_non_empty_regex() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("file"), b"")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("file"),
            regex: regex::Regex::new("").unwrap(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn handle_regex_no_matches() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("file"), b"foo")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("file"),
            regex: regex::Regex::new("bar").unwrap(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 0);
    }

    #[test]
    fn handle_regex_single_match() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("file"), b"bar")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("file"),
            regex: regex::Regex::new("bar").unwrap(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.content, "bar");
    }

    #[test]
    fn handle_regex_multiple_matches_multiple_lines() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("file"), b"bar\nbas\nbaz\nbar")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("file"),
            regex: regex::Regex::new("ba[rz]").unwrap(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.content, "bar");

        let item = session.reply::<Item>(1);
        assert_eq!(item.offset, 8);
        assert_eq!(item.content, "baz");

        let item = session.reply::<Item>(2);
        assert_eq!(item.offset, 12);
        assert_eq!(item.content, "bar");
    }

    #[test]
    fn handle_regex_multiple_matches_single_line() {
        let tempdir = tempfile::tempdir()
            .unwrap();

        std::fs::write(tempdir.path().join("file"), b"bar bas baz bar")
            .unwrap();

        let args = Args {
            path: tempdir.path().join("file"),
            regex: regex::Regex::new("ba[rz]").unwrap(),
        };

        let mut session = crate::session::FakeSession::new();
        handle(&mut session, args)
            .unwrap();

        assert_eq!(session.reply_count(), 3);

        let item = session.reply::<Item>(0);
        assert_eq!(item.offset, 0);
        assert_eq!(item.content, "bar");

        let item = session.reply::<Item>(1);
        assert_eq!(item.offset, 8);
        assert_eq!(item.content, "baz");

        let item = session.reply::<Item>(2);
        assert_eq!(item.offset, 12);
        assert_eq!(item.content, "bar");
    }
}
