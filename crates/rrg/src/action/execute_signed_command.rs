// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// We need to make combined `MAX_STD*_SIZE` around 1 MiB limit not to exceed the
// Fleetspeak message size restrictions. We could make one bigger at the expense
// of the other one but it is not clear which should take priority, so to keep
// things simple and balanced we set the same value for both.
const MAX_STDOUT_SIZE: usize = 512 * 1024; // 512 KiB.
const MAX_STDERR_SIZE: usize = 512 * 1024; // 512 KiB.

const COMMAND_EXECUTION_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

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
    exit_status: std::process::ExitStatus,
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
struct CommandExecutionError(std::io::Error);

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
    use std::io::{Read as _, Write as _};
    use crate::request::ParseArgsError;

    match session.args().command_verification_key {
        Some(key) => key
            .verify_strict(&args.raw_command, &args.ed25519_signature)
            .map_err(|error| ParseArgsError::invalid_field("raw_command", error))?,
        None => return Err(crate::session::Error::action(MissingCommandVerificationKeyError)),
    };

    let mut command_process = std::process::Command::new(&args.path)
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
    let command_stdout = command_process.stdout.take()
        .expect("no stdout pipe");
    let command_stderr = command_process.stderr.take()
        .expect("no stderr pipe");

    // We need to write stdin that we have in a separate thread because on one
    // hand the subprocess can wait for input and on the other hand it can also
    // produce output that needs to be consumed.
    //
    // Consider a `cat` command without any arguments. It will pipe all of its
    // standard input to the standard output. Imagine it is called with a lot of
    // input data. It will consume part of the input and write this bit to the
    // output. This will continue until the output pipe is full. However, if we
    // attempt to write everything at once on the main thread, we will never get
    // to the reading part. And thus we will be stuck on writing to the child
    // and the child will be stuck on writing back to us (due to the pipe being
    // full). Thus, we use threading for producing the input and consuming the
    // output at the same time.
    //
    // As an optimization (because spawning a thread has a non-zero cost) we do
    // spawn a thread only if there is any input to be written.
    let writer = if !args.stdin.is_empty() {
        Some(std::thread::spawn(move || -> std::io::Result<()> {
            command_stdin.write_all(&args.stdin)?;

            // Dropping the pipe below will flush it but will swallow all poten-
            // tial errors while doing so. Thus, we flush explicitly here to be
            // able to catch all errors.
            command_stdin.flush()?;

            // We explictly drop the pipe to notify the spawned command that
            // there is no more input incoming.
            drop(command_stdin);

            Ok(())
        }))
    } else {
        None
    };

    // See the comment above on why we need threading to read output from the
    // subprocess.
    //
    // Note that we need two reader threads because we cannot guarantee which of
    // the pipes should take precedence—the command might need to write a lot of
    // data to either of them. So, we start consuming from both of them at the
    // same time.

    let reader_stdout = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut stdout = Vec::<u8>::new();

        let mut command_stdout_limited = command_stdout.take(MAX_STDOUT_SIZE as u64);
        command_stdout_limited.read_to_end(&mut stdout)?;

        // We are interested only in the first part of the output, but we need
        // to consume everything in case there is more to prevent the child from
        // blocking on full pipe.
        let mut command_stdout = command_stdout_limited.into_inner();
        match std::io::copy(&mut command_stdout, &mut std::io::sink()) {
            // We are fine either with end of output or broken pipe (which might
            // happen if the child is killed or finishes).
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => (),
            Err(error) => return Err(error),
        }

        Ok(stdout)
    });

    let reader_stderr = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut stderr = Vec::<u8>::new();

        let mut command_stderr_limited = command_stderr.take(MAX_STDERR_SIZE as u64);
        command_stderr_limited.read_to_end(&mut stderr)?;

        // We are interested only in the first part of the output, but we need
        // to consume everything in case there is more to prevent the child from
        // blocking on full pipe.
        let mut command_stderr = command_stderr_limited.into_inner();
        match std::io::copy(&mut command_stderr, &mut std::io::sink()) {
            // We are fine either with end of output or broken pipe (which might
            // happen if the child is killed or finishes).
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => (),
            Err(error) => return Err(error),
        }

        Ok(stderr)
    });

    log::info!("starting '{}' (timeout: {:?})", args.path.display(), args.timeout);
    loop {
        let time_elapsed = command_start_time.elapsed();
        let time_left = args.timeout.saturating_sub(time_elapsed);

        if time_left.is_zero() {
            break;
        }

        match command_process.try_wait() {
            Ok(None) => {
                std::thread::sleep(std::cmp::min(COMMAND_EXECUTION_CHECK_INTERVAL, time_left));
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

    if let Some(writer) = writer {
        match writer.join() {
            Ok(Ok(())) => (),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                // We ignore broken pipe errors when writing as this can happen
                // if the action finished early or timed out.
            }
            Ok(Err(error)) => {
                return Err(crate::session::Error::action(CommandExecutionError(error)))
            }
            Err(error) => std::panic::resume_unwind(error),
        }
    }

    let stdout = match reader_stdout.join() {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(error)) => {
            return Err(crate::session::Error::action(CommandExecutionError(error)))
        }
        Err(error) => std::panic::resume_unwind(error),
    };

    let stderr = match reader_stderr.join() {
        Ok(Ok(stderr)) => stderr,
        Ok(Err(error)) => {
            return Err(crate::session::Error::action(CommandExecutionError(error)))
        }
        Err(error) => std::panic::resume_unwind(error),
    };

    session.reply(Item {
        exit_status,
        // Note that we will return `truncated_std*` bit even if the output was
        // exactly `MAX_STD*_SIZE`. However, because this constant is an agent
        // implementation detail we might have as well set it to be 1 more than
        // it is right now and we just shift the "problem". Thus, it really does
        // not matter but makes the code simpler.
        truncated_stdout: stdout.len() == MAX_STDOUT_SIZE,
        truncated_stderr: stderr.len() == MAX_STDERR_SIZE,
        stdout,
        stderr,
    })?;

    Ok(())
}

impl crate::request::Args for Args {
    type Proto = rrg_proto::execute_signed_command::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;
        use protobuf::Message as _;

        let raw_signature = proto.take_command_ed25519_signature();

        let ed25519_signature = ed25519_dalek::Signature::try_from(&raw_signature[..])
            .map_err(|error| ParseArgsError::invalid_field("command_ed25519_signature", error))?;

        let raw_command = proto.take_command();
        let mut command =
            rrg_proto::execute_signed_command::Command::parse_from_bytes(&raw_command)
                .map_err(|error| ParseArgsError::invalid_field("command", error))?;

        let path = std::path::PathBuf::try_from(command.take_path())
            .map_err(|error| ParseArgsError::invalid_field("command path", error))?;

        let stdin = match command.unsigned_stdin_allowed() {
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

    use ed25519_dalek::Signer as _;

    use super::*;

    fn prepare_session(verification_key: ed25519_dalek::VerifyingKey) -> crate::session::FakeSession {
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
            path: "echo".into(),
            args: ["Hello,", "world!"]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
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
            path: "cmd".into(),
            args: ["/C", "echo", "Hello,", "world!"]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
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
            path: "cat".into(),
            args: Vec::default(),
            env: std::collections::HashMap::new(),
            stdin: "Hello, world!".as_bytes().to_vec(),
            ed25519_signature,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
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
            path: "findstr".into(),
            args: vec![String::from("world")],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: "Hello, world!".as_bytes().to_vec(),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "Hello, world!\r\n".as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_env() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "printenv".into(),
            args: Vec::default(),
            env: [(String::from("MY_ENV_VAR"), String::from("Hello, world!"))]
                .into(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);

        let stdout = String::from_utf8_lossy(&item.stdout);
        assert!(stdout.contains("MY_ENV_VAR=Hello, world!"));
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_env() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "cmd".into(),
            args: vec![String::from("/c"), String::from("echo %MY_ENV_VAR%")],
            env: [(String::from("MY_ENV_VAR"), String::from("Hello, world!"))]
                .into(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "Hello, world!\r\n".as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[test]
    fn handle_invalid_signature() {
        use protobuf::Message as _;
        use crate::request::Args as _;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::Command::new();
        command.set_path(std::path::PathBuf::from("ls").into());

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

        assert!(handle(&mut session, args).is_err());
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
            path: "cat".into(),
            args: Vec::default(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: ("A".repeat(MAX_STDOUT_SIZE) + "truncated").into_bytes(),
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "A".repeat(MAX_STDOUT_SIZE).as_bytes());
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

        // There is no direct analogue to `cat` on Windows but `findstr` can act
        // similarly: it behaves like `grep`, outputing lines from the input
        // that match the given expression.
        //
        // What we do in this test is we provide a lot of "ABCD" lines and we
        // want to match each of them. Each line in the output will have its
        // own CLRF char and one extra (provided by `finstr`), so 8 bytes total.
        // Thus, we expect `MAX_STDOUT_SIZE / 8` such entries in the output (the
        // length of the "ABCD" string was chosen so that `MAX_STDOUT_SIZE` is
        // evenly divisible by the output string length).
        //
        // The input "ABCD" line is repeated `MAX_STDOUT_SIZE` number of times,
        // so the total untruncated output size should be much bigger than the
        // limit.

        let args = Args {
            raw_command,
            path: "findstr".into(),
            args: vec![String::from("ABCD")],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from("ABCD\r\n".repeat(MAX_STDOUT_SIZE)),
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "ABCD\r\n\r\n".repeat(MAX_STDOUT_SIZE / 8).as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_kill_if_timeout() {
        let timeout = std::time::Duration::from_secs(0);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "sleep".into(),
            args: vec![(timeout.as_secs() + 1).to_string()],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout,
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        use std::os::unix::process::ExitStatusExt as _;

        assert!(!item.exit_status.success());
        assert_eq!(item.exit_status.signal(), Some(libc::SIGKILL));
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, b"");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_kill_if_timeout_large_stdin() {
        let timeout = std::time::Duration::from_secs(0);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        // In this test we pipe 2 MiB of data to `sleep` to verify that there is
        // no deadlock when writing input. `sleep` does not consume anthing, so
        // it should eventually start blocking—the timeout logic should still
        // work despite that.

        let args = Args {
            raw_command,
            path: "sleep".into(),
            args: vec![(timeout.as_secs() + 1).to_string()],
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: vec![0xFF; 2 * 1024 * 1024],
            timeout,
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        use std::os::unix::process::ExitStatusExt as _;

        assert!(!item.exit_status.success());
        assert_eq!(item.exit_status.signal(), Some(libc::SIGKILL));
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, b"");
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_kill_if_timeout() {
        let timeout = std::time::Duration::from_secs(0);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            // The `timeout` command seems to be unavailable e.g. on Wine so
            // instead we just hang the program forever using an infinite loop.
            path: "cmd".into(),
            args: ["/q", "/c", "for /l %i in () do echo off"]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout,
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(!item.exit_status.success());
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, b"");
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_kill_if_timeout_large_stdin() {
        let timeout = std::time::Duration::from_secs(0);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        // In this test we pipe 2 MiB of data to the subprocess to verify that
        // there is no deadlock when writing input. The subprocess does not con-
        // sume anthing and will eventually start blocking and the timeout logic
        // should still work despite that.

        let args = Args {
            raw_command,
            // The `timeout` command seems to be unavailable e.g. on Wine so
            // instead we just hang the program forever using an infinite loop.
            path: "cmd".into(),
            args: ["/q", "/c", "for /l %i in () do echo off"]
                .into_iter().map(String::from).collect(),
            env: std::collections::HashMap::new(),
            ed25519_signature,
            stdin: vec![0xFF; 2 * 1024 * 1024],
            timeout,
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(!item.exit_status.success());
        assert_eq!(item.stderr, b"");
        assert_eq!(item.stdout, b"");
    }
}
