// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::{
    fmt::Debug,
    io::{Read, Write},
    process::{Command, ExitStatus},
};

use protobuf::Message;

// TODO(s-westphal): Check and update max size.
const MAX_OUTPUT_SIZE: usize = 4048;
const COMMAND_EXECUTION_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Arguments of the `execute_signed_command` action.
pub struct Args {
    raw_command: Vec<u8>,
    /// Path to the executable file to execute.
    path: std::path::PathBuf,
    /// Command-line arguments to pass to the executable.
    args: Vec<String>,
    /// Environment in which to invoke the executable.
    env: std::collections::HashMap<String, String>,
    stdin: Vec<u8>,
    ed25519_signature: ed25519_dalek::Signature,
    timeout: std::time::Duration,
}

/// Result of the `execute_signed_command` action.
pub struct Item {
    /// Exit status of the command subprocess.
    exit_status: ExitStatus,
    /// Standard output of the command executiom.
    stdout: Vec<u8>,
    /// Wheather standard output is truncated.
    truncated_stdout: bool,
    /// Standard error of the command executiom.
    stderr: Vec<u8>,
    /// Wheather stderr is truncated.
    truncated_stderr: bool,
}

/// An error indicating that the command signature is missing.
#[derive(Debug)]
struct MissingCommandVerificationKeyError;

impl std::fmt::Display for MissingCommandVerificationKeyError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "missing command verification key")
    }
}

impl std::error::Error for MissingCommandVerificationKeyError {}

/// An error indicating that stdin of the command couln't be captured.
#[derive(Debug)]
struct CommandExecutionError(Box<dyn std::any::Any + Send + 'static>);

impl std::fmt::Display for CommandExecutionError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "failed to execute the command: {:?}", self.0)
    }
}

impl std::error::Error for CommandExecutionError {}

/// Handles invocations of the `execute_signed_command` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use crate::request::ParseArgsError;

    match session.args().command_verification_key {
        Some(key) => key
            .verify_strict(&args.raw_command, &args.ed25519_signature)
            .map_err(|error| ParseArgsError::invalid_field("raw_command", error))?,
        None => return Err(crate::session::Error::action(MissingCommandVerificationKeyError)),
    };

    let mut command_process = Command::new(args.path)
        .stdin(std::process::Stdio::piped())
        .args(args.args)
        .env_clear()
        .envs(args.env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(crate::session::Error::action)?;

    let command_start_time = std::time::Instant::now();

    let mut command_stdin = command_process.stdin.take()
        .expect("no stdin pipe");

    let handle = std::thread::spawn(move || {
        // While writing an empty stdin should be a no-op, it is possible for
        // the command to finish executing before we get to the writing part and
        // the pipe will be closed. We could just ignore "broken pipe" errors
        // but they can be relevant in case we did have something to write. So,
        // we just avoid writing altogether if there is nothing to be written.
        if args.stdin.is_empty() {
            return;
        }

        command_stdin
            .write(&args.stdin[..])
            .expect("failed to write to stdin");
    });

    handle.join()
        .map_err(CommandExecutionError)
        .map_err(crate::session::Error::action)?;

    while command_start_time.elapsed() < args.timeout {
        match command_process.try_wait() {
            Ok(None) => {
                log::debug!(
                    "command not completed, waiting {:?}",
                    COMMAND_EXECUTION_CHECK_INTERVAL
                );
                std::thread::sleep(COMMAND_EXECUTION_CHECK_INTERVAL);
            }
            _ => break,
        }
    }
    // Either the process has exited, then kill doesn't do anything,
    // or we kill the process.
    command_process
        .kill()
        .map_err(crate::session::Error::action)?;

    let exit_status = command_process
        .wait()
        .map_err(crate::session::Error::action)?;

    let mut stdout = Vec::<u8>::new();
    command_process.stdout
        .expect("no stdout pipe")
        .take(MAX_OUTPUT_SIZE as u64).read_to_end(&mut stdout)
        .map_err(crate::session::Error::action)?;

    let mut stderr = Vec::<u8>::new();
    command_process.stderr
        .expect("no stderr pipe")
        .take(MAX_OUTPUT_SIZE as u64).read_to_end(&mut stderr)
        .map_err(crate::session::Error::action)?;

    session.reply(Item {
        exit_status,
        // Note that we will return `truncated_std*` bit even if the output was
        // exactly `MAX_OUTPUT_SIZE`. However, because this constant is an agent
        // implementation detail we might have as well set it to be 1 more than
        // it is right now and we just shift the "problem". Thus, it really does
        // not matter but makes the code simpler.
        truncated_stdout: stdout.len() == MAX_OUTPUT_SIZE,
        truncated_stderr: stderr.len() == MAX_OUTPUT_SIZE,
        stdout,
        stderr,
    })?;

    Ok(())
}

impl crate::request::Args for Args {
    type Proto = rrg_proto::execute_signed_command::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let raw_signature = proto.take_command_ed25519_signature();

        let ed25519_signature = ed25519_dalek::Signature::try_from(&raw_signature[..])
            .map_err(|error| ParseArgsError::invalid_field("command_ed25519_signature", error))?;

        let raw_command = proto.take_command();
        let mut command =
            rrg_proto::execute_signed_command::SignedCommand::parse_from_bytes(&raw_command)
                .map_err(|error| ParseArgsError::invalid_field("command", error))?;

        let path = std::path::PathBuf::try_from(command.take_path())
            .map_err(|error| ParseArgsError::invalid_field("command path", error))?;

        let stdin = match command.unsigned_stdin() {
            true => proto.take_unsigned_stdin(),
            false => command.take_signed_stdin(),
        };

        let timeout = std::time::Duration::try_from(proto.take_timeout())
            .map_err(|error| ParseArgsError::invalid_field("timeout", error))?;

        Ok(Args {
            raw_command,
            path,
            args: command.take_args(),
            env: command.take_env(),
            ed25519_signature,
            stdin,
            timeout,
        })
    }
}

impl crate::response::Item for Item {
    type Proto = rrg_proto::execute_signed_command::Result;

    fn into_proto(self) -> Self::Proto {
        let mut proto = rrg_proto::execute_signed_command::Result::new();

        if let Some(exit_code) = self.exit_status.code() {
            proto.set_exit_code(exit_code);
        }

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::process::ExitStatusExt as _;

            if let Some(exit_signal) = self.exit_status.signal() {
                proto.set_exit_signal(exit_signal);
            }
        }

        proto.set_stdout(self.stdout);
        proto.set_stdout_truncated(self.truncated_stdout);

        proto.set_stderr(self.stderr);
        proto.set_stderr_truncated(self.truncated_stderr);

        proto
    }
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use ed25519_dalek::{Signer, VerifyingKey};

    use crate::session::FakeSession;

    use super::*;

    fn prepare_session(verification_key: VerifyingKey) -> FakeSession {
        crate::session::FakeSession::with_args(crate::args::Args {
            heartbeat_rate: std::time::Duration::from_secs(0),
            command_verification_key: Some(verification_key),
            verbosity: log::LevelFilter::Debug,
            log_to_stdout: false,
            log_to_file: None,
        })
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_command_args() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("echo"),
            args: ["Hello,", "world!"]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, "Hello, world!\n".as_bytes());
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_command_args() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("cmd"),
            args: ["/C", "echo", "Hello,", "world!"]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, "Hello, world!\r\n".as_bytes());
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_stdin() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("cat"),
            args: Vec::default(),
            env: std::collections::HashMap::new(),
            stdin: "Hello, world!".as_bytes().to_vec(),
            ed25519_signature,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "Hello, world!".as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_stdin() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("cmd"),
            args: ["/C", "C:\\Windows\\System32\\findstr ."]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: "Hello, world!".as_bytes().to_vec(),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "Hello, world!\r\n".as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[test]
    fn handle_env() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("printenv"),
            args: Vec::default(),
            env: [(String::from("MY_ENV_VAR"), String::from("Hello, world!"))]
                .into(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert!(String::from_utf8_lossy(&item.stdout)
            .find("MY_ENV_VAR=Hello, world!")
            .is_some());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[test]
    fn handle_invalid_signature() {
        use crate::request::Args as _;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();
        command.set_path(PathBuf::from("ls").into());

        let raw_command = command.write_to_bytes().unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&raw_command).to_vec());
        args_proto.set_command(raw_command);
        args_proto.mut_timeout().seconds = 5;

        let mut args = Args::from_proto(args_proto)
            .unwrap();

        let invalid_signature_bytes: [u8; 64] = [4_u8; 64]; //  random bytes.
        let invalid_signature = ed25519_dalek::Signature::from_bytes(&invalid_signature_bytes);

        args.ed25519_signature = invalid_signature;

        let _ = handle(&mut session, args).is_err();
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_truncate_output() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("echo"),
            args: vec!["A".repeat(MAX_OUTPUT_SIZE) + "truncated"],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "A".repeat(MAX_OUTPUT_SIZE).as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_truncate_output() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("cmd"),
            args: vec![
                String::from("/C"),
                String::from("echo"),
                "A".repeat(MAX_OUTPUT_SIZE) + "truncated",
            ],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "A".repeat(MAX_OUTPUT_SIZE).as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[test]
    fn handle_kill_if_timeout() {
        let timeout = std::time::Duration::from_secs(5);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: PathBuf::from("sleep"),
            args: vec![(timeout.as_secs() + 1).to_string()],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout,
        };

        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(!item.exit_status.success());
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::process::ExitStatusExt;

            assert_eq!(item.exit_status.signal(), Some(libc::SIGKILL));
        }
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, b"");
    }
}
