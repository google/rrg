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
    args: Vec<CommandArg>,
    /// Environment in which to invoke the executable.
    env: std::collections::HashMap<String, String>,
    /// Environment variables which to inherit from the current process.
    env_inherited: Vec<String>,
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
    /// Whether standard output is truncated.
    truncated_stdout: bool,
    /// Standard error of the command executiom.
    stderr: Vec<u8>,
    /// Whether stderr is truncated.
    truncated_stderr: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum CommandArg {
    Literal(String),
    FileId(String),
}

impl CommandArg {

    fn literal<S: Into<String>>(string: S) -> CommandArg {
        CommandArg::Literal(string.into())
    }

    fn file_id<S: Into<String>>(file_id: S) -> CommandArg {
        CommandArg::FileId(file_id.into())
    }
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

/// An error indicating that stdin of the command couldn't be captured.
#[derive(Debug)]
struct CommandExecutionError(std::io::Error);

impl std::fmt::Display for CommandExecutionError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "failed to execute the command: {:?}", self.0)
    }
}

// An error indicating that the unsigned arg was required but not provided.
#[derive(Debug)]
struct MissingUnsignedArgError {
    idx: usize,
}

impl std::fmt::Display for MissingUnsignedArgError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "missing unsigned arg at {}", self.idx)
    }
}

impl std::error::Error for MissingUnsignedArgError {}

// An error indicating that there are more unsigned args provided than expected.
#[derive(Debug)]
struct ExcessiveUnsignedArgsError {
    count: usize,
}

impl std::fmt::Display for ExcessiveUnsignedArgsError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{} excessive unsigned arguments", self.count)
    }
}

impl std::error::Error for ExcessiveUnsignedArgsError {}

impl std::error::Error for CommandExecutionError {}

/// An error indicating that the given unsigned environment variable was not
/// allowed.
#[derive(Debug)]
struct UnallowedUnsignedEnvError {
    name: String,
}

impl std::fmt::Display for UnallowedUnsignedEnvError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "'{}' not allowed as unsigned", self.name)
    }
}

impl std::error::Error for UnallowedUnsignedEnvError {}

/// An error indicating that the given unsigned environment variable has
/// conflicting values.
#[derive(Debug)]
struct DupUnsignedEnvError {
    name: String,
}

impl std::fmt::Display for DupUnsignedEnvError {

    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "'{}' not allowed as unsigned", self.name)
    }
}

impl std::error::Error for DupUnsignedEnvError {}

/// Handles invocations of the `execute_signed_command` action.
pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    use std::io::{Read as _, Write as _};
    use crate::request::ParseArgsError;

    #[cfg(feature = "action-execute_signed_command-preverified")]
    {
        #[derive(Debug)]
        struct InvalidPreverifiedCommandsError(protobuf::Error);

        impl std::fmt::Display for InvalidPreverifiedCommandsError {

            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "invalid preverified commands: {}", self.0)
            }
        }

        impl std::error::Error for InvalidPreverifiedCommandsError {

            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        #[derive(Debug)]
        struct PreverifiedCommandError;

        impl std::fmt::Display for PreverifiedCommandError {

            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "no matching preverified command found")
            }
        }

        impl std::error::Error for PreverifiedCommandError {
        }

        use protobuf::Message as _;

        let commands = rrg_proto::execute_signed_command::CommandList::parse_from_bytes({
            include_bytes!(env!("RRG_EXECUTE_SIGNED_COMMAND_PREVERIFIED"))
        }).map_err(|error| crate::session::Error::action(InvalidPreverifiedCommandsError(error)))?;

        if !commands.commands().iter().any(|command| &args.raw_command == command) {
            return Err(ParseArgsError::invalid_field("command", PreverifiedCommandError).into());
        }
    }

    #[cfg(not(feature = "action-execute_signed_command-preverified"))]
    match session.args().command_verification_key {
        Some(key) => key
            .verify_strict(&args.raw_command, &args.ed25519_signature)
            .map_err(|error| ParseArgsError::invalid_field("raw_command", error))?,
        None => return Err(crate::session::Error::action(MissingCommandVerificationKeyError)),
    };

    let env_inherited = args.env_inherited.iter()
        .filter_map(|var| match std::env::var(var) {
            Ok(value) => Some((var, value)),
            Err(error) => {
                log::warn!("failed to inherit '{var}': {error}");
                None
            }
        });

    let command_args = args.args.into_iter()
        .map(|arg| match arg {
            CommandArg::Literal(string) => {
                Ok(std::ffi::OsString::from(string))
            }
            CommandArg::FileId(file_id) => {
                Ok(session.filestore_path(&file_id)?.into_os_string())
            }
        }).collect::<crate::session::Result<Vec<_>>>()?;

    let mut command_process = std::process::Command::new(&args.path)
        .stdin(std::process::Stdio::piped())
        .args(command_args)
        .env_clear()
        .envs(env_inherited)
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

            // We explicitly drop the pipe to notify the spawned command that
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

    log::info! {
        "done executing '{}' after {:?}, exit status: {}",
        args.path.display(),
        command_start_time.elapsed(),
        exit_status,
    };

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

        let mut args = Vec::new();

        // We use `args_signed` for compatibility reasons. Once the field is not
        // in active use anymore, this should be deleted.
        args.extend(command.take_args_signed().into_iter().map(CommandArg::literal));

        let mut unsigned_args_iter = proto.take_unsigned_args().into_iter();
        let mut file_ids_iter = proto.take_file_ids().into_iter();

        for (arg_idx, mut arg) in command.take_args().into_iter().enumerate() {
            let arg = if arg.unsigned_allowed() {
                match unsigned_args_iter.next() {
                    Some(arg) => CommandArg::literal(arg),
                    None => {
                        return Err(ParseArgsError::invalid_field("unsigned args", MissingUnsignedArgError {
                            idx: arg_idx,
                        }))
                    }
                }
            } else if arg.file_id_allowed() {
                match file_ids_iter.next() {
                    Some(file_id) => CommandArg::file_id(file_id),
                    None => todo!(),
                }
            } else {
                CommandArg::literal(arg.take_signed())
            };

            args.push(arg);
        }
        let unsigned_args_left = unsigned_args_iter.count();
        if unsigned_args_left > 0 {
            return Err(ParseArgsError::invalid_field("unsigned args", ExcessiveUnsignedArgsError {
                count: unsigned_args_left,
            }));
        }

        let mut env = std::collections::HashMap::new();
        env.extend(command.take_env_signed());

        for (name, value) in proto.take_unsigned_env().into_iter() {
            if !command.env_unsigned_allowed().contains(&name) {
                return Err(ParseArgsError::invalid_field("unsigned env", UnallowedUnsignedEnvError {
                    name,
                }))
            }

            use std::collections::hash_map::Entry::*;
            match env.entry(name) {
                Vacant(entry) => {
                    entry.insert(value);
                }
                Occupied(entry) => {
                    return Err(ParseArgsError::invalid_field("unsigned env", DupUnsignedEnvError {
                        name: String::from(entry.key()),
                    }))
                }
            }
        }

        let stdin = match command.unsigned_stdin_allowed() {
            true => proto.take_unsigned_stdin(),
            false => command.take_signed_stdin(),
        };

        let timeout = std::time::Duration::try_from(proto.take_timeout())
            .map_err(|error| ParseArgsError::invalid_field("timeout", error))?;

        Ok(Args {
            raw_command,
            path,
            args,
            env,
            env_inherited: command.take_env_inherited(),
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
// TODO: https://github.com/google/rrg/issues/137
//
// Most of these tests rely on custom commands which does not work with the
// predefined mode. Once support for predefined commands is gone, we can enable
// them for all builds again.
#[cfg(not(feature = "action-execute_signed_command-preverified"))]
mod tests {

    use ed25519_dalek::Signer as _;

    use super::*;

    fn prepare_session(verification_key: ed25519_dalek::VerifyingKey) -> crate::session::FakeSession {
        crate::session::FakeSession::with_args(crate::args::Args {
            heartbeat_rate: std::time::Duration::from_secs(0),
            ping_rate: std::time::Duration::from_secs(0),
            command_verification_key: Some(verification_key),
            verbosity: log::LevelFilter::Debug,
            log_to_stdout: false,
            log_to_file: None,
            filestore_dir: None,
            filestore_ttl: std::time::Duration::ZERO,
        })
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_command_args_literal() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "echo".into(),
            args: ["Hello,", "world!"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_command_args_file_id() {
        use crate::session::Session as _;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key())
            .with_filestore();

        session.filestore_store("foo", crate::filestore::Part {
            offset: 0,
            content: b"Lorem ipsum.\n".to_vec(),
            file_len: b"Lorem ipsum.\n".len() as u64,
            file_sha256: sha256(b"Lorem ipsum.\n"),
        }).unwrap();

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "cat".into(),
            args: [CommandArg::file_id("foo")]
                .into(),
            env: std::collections::HashMap::new(),
            env_inherited: vec![],
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "Lorem ipsum.\n".as_bytes());
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_command_args_literal() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "cmd".into(),
            args: ["/C", "echo", "Hello,", "world!"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_command_args_file_id() {
        use crate::session::Session as _;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key())
            .with_filestore();

        session.filestore_store("foo", crate::filestore::Part {
            offset: 0,
            content: b"Lorem ipsum.\r\n".to_vec(),
            file_len: b"Lorem ipsum.\r\n".len() as u64,
            file_sha256: sha256(b"Lorem ipsum.\r\n"),
        }).unwrap();

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "findstr".into(),
            args: [CommandArg::literal("ipsum"), CommandArg::file_id("foo")]
                .into(),
            env: std::collections::HashMap::new(),
            env_inherited: vec![],
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();

        assert_eq!(session.reply_count(), 1);

        let item = session.reply::<Item>(0);
        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "Lorem ipsum.\r\n".as_bytes());
        assert_eq!(item.stderr, b"");
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
            env_inherited: Vec::new(),
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
            args: ["world"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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
    fn handle_stdin_unconsumed() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "true".into(),
            args: Vec::default(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
            // In this test we write a lot of input to a command that does not
            // care about it. This is to verify that we are never stuck on wri-
            // ting even if it is never consumed.
            stdin: vec![0xFF; 2 * 1024 * 1024],
            ed25519_signature,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, b"");
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_stdin_unconsumed() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "cmd".into(),
            args: ["/c", "exit"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
            // In this test we write a lot of input to a command that does not
            // care about it. This is to verify that we are never stuck on wri-
            // ting even if it is never consumed.
            stdin: vec![0xFF; 2 * 1024 * 1024],
            ed25519_signature,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, b"");
        assert_eq!(item.stderr, b"");
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
    }

    // `/dev/zero` is specific to Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn handle_stdout_large() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            // In this test we read large amount of data from the output of the
            // child process. This should ensure we always consume the data and
            // never get stuck on a full pipe.
            path: "head".into(),
            args: ["--bytes=67108864" /* 64 MiB */, "/dev/zero"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
            stdin: Vec::default(),
            ed25519_signature,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());

        assert_eq!(item.stdout.len(), MAX_STDOUT_SIZE);
        assert!(item.stdout.iter().all(|byte| *byte == 0x00));
        assert!(item.truncated_stdout);

        assert_eq!(item.stderr, b"");
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
            env_inherited: Vec::new(),
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
            args: ["/c", "echo %MY_ENV_VAR%"]
                .map(CommandArg::literal).into(),
            env: [(String::from("MY_ENV_VAR"), String::from("Hello, world!"))]
                .into(),
            env_inherited: Vec::new(),
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

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_env_inherited() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "printenv".into(),
            args: Vec::default(),
            env: std::collections::HashMap::new(),
            env_inherited: vec![String::from("PATH")],
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
        match std::env::var("PATH") {
            Ok(path) => assert!(stdout.contains(&format!("PATH={path}"))),
            Err(_) => assert!(!stdout.contains("PATH=")),
        }
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_env_inherited() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "cmd".into(),
            args: ["/c", "echo %SystemRoot%"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: vec![String::from("SystemRoot")],
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
        assert!(stdout.to_uppercase().contains("WINDOWS"));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn handle_env_inherited_explicit() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "printenv".into(),
            args: Vec::default(),
            env: [(String::from("HOME"), String::from("/tmp"))]
                .into(),
            env_inherited: vec![String::from("HOME")],
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
        assert!(stdout.contains(&format!("HOME=/tmp")));
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn handle_env_inherited_explicit() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let raw_command = Vec::default();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            path: "cmd".into(),
            args: ["/c", "echo %TEMP%"]
                .map(CommandArg::literal).into(),
            env: [(String::from("TEMP"), String::from("C:\\Foo\\Bar"))]
                .into(),
            env_inherited: vec![String::from("TEMP")],
            ed25519_signature,
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        assert_eq!(item.stdout, "C:\\Foo\\Bar\r\n".as_bytes());
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
            env_inherited: Vec::new(),
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
        // similarly: it behaves like `grep`, outputting lines from the input
        // that match the given expression.
        //
        // What we do in this test is we provide a lot of "ABCD" lines and we
        // want to match each of them. The input line is repeated enough times,
        // for the truncation logic to kick in.

        let args = Args {
            raw_command,
            path: "findstr".into(),
            args: ["ABCD"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
            ed25519_signature,
            stdin: Vec::from("ABCD\r\n".repeat(MAX_STDOUT_SIZE)),
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        assert_eq!(session.reply_count(), 1);
        let item = session.reply::<Item>(0);

        assert!(item.exit_status.success());
        // Different environments seem to use slightly different output for
        // `findstr` (sometimes there is an extra newline, sometimes there is
        // not), so we only verify the very beginning and then just compare the
        // expected truncated length.
        assert!(item.stdout.starts_with(b"ABCD"));
        assert_eq!(item.stdout.len(), MAX_STDOUT_SIZE);
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
            args: [(timeout.as_secs() + 1).to_string()]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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
        // no deadlock when writing input. `sleep` does not consume anything, so
        // it should eventually start blocking—the timeout logic should still
        // work despite that.

        let args = Args {
            raw_command,
            path: "sleep".into(),
            args: [(timeout.as_secs() + 1).to_string()]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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
        // sume anything and will eventually start blocking and the timeout logic
        // should still work despite that.

        let args = Args {
            raw_command,
            // The `timeout` command seems to be unavailable e.g. on Wine so
            // instead we just hang the program forever using an infinite loop.
            path: "cmd".into(),
            args: ["/q", "/c", "for /l %i in () do echo off"]
                .map(CommandArg::literal).into(),
            env: std::collections::HashMap::new(),
            env_inherited: Vec::new(),
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

    #[test]
    fn args_from_proto_args_signed() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());
        command_proto.mut_args_signed().push(String::from("foo"));
        command_proto.mut_args_signed().push(String::from("bar"));

        let mut arg_quux = rrg_proto::execute_signed_command::command::Arg::new();
        arg_quux.set_signed(String::from("quux"));
        command_proto.mut_args().push(arg_quux);

        let mut arg_norf = rrg_proto::execute_signed_command::command::Arg::new();
        arg_norf.set_signed(String::from("norf"));
        command_proto.mut_args().push(arg_norf);

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);

        let args = <Args as crate::request::Args>::from_proto(args_proto)
            .unwrap();
        assert_eq!(args.path, std::path::Path::new("/foo/bar"));
        assert_eq!(args.args, [
            CommandArg::literal("foo"),
            CommandArg::literal("bar"),
            CommandArg::literal("quux"),
            CommandArg::literal("norf"),
        ]);
    }

    #[test]
    fn args_from_proto_args_unsigned() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());

        let mut arg_quux = rrg_proto::execute_signed_command::command::Arg::new();
        arg_quux.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_quux);

        let mut arg_norf = rrg_proto::execute_signed_command::command::Arg::new();
        arg_norf.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_norf);

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_args().push(String::from("quux"));
        args_proto.mut_unsigned_args().push(String::from("norf"));

        let args = <Args as crate::request::Args>::from_proto(args_proto)
            .unwrap();
        assert_eq!(args.path, std::path::Path::new("/foo/bar"));
        assert_eq!(args.args, [
            CommandArg::literal("quux"),
            CommandArg::literal("norf"),
        ]);
    }

    #[test]
    fn args_form_proto_args_mixed() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());

        let mut arg_quux = rrg_proto::execute_signed_command::command::Arg::new();
        arg_quux.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_quux);

        let mut arg_norf = rrg_proto::execute_signed_command::command::Arg::new();
        arg_norf.set_signed(String::from("norf"));
        command_proto.mut_args().push(arg_norf);

        let mut arg_thud = rrg_proto::execute_signed_command::command::Arg::new();
        arg_thud.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_thud);

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_args().push(String::from("quux"));
        args_proto.mut_unsigned_args().push(String::from("thud"));

        let args = <Args as crate::request::Args>::from_proto(args_proto)
            .unwrap();
        assert_eq!(args.path, std::path::Path::new("/foo/bar"));
        assert_eq!(args.args, [
            CommandArg::literal("quux"),
            CommandArg::literal("norf"),
            CommandArg::literal("thud"),
        ]);
    }

    #[test]
    fn args_from_proto_args_unsigned_missing() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());

        let mut arg_quux = rrg_proto::execute_signed_command::command::Arg::new();
        arg_quux.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_quux);

        let mut arg_norf = rrg_proto::execute_signed_command::command::Arg::new();
        arg_norf.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_norf);

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_args().push(String::from("quux"));

        // TODO(@panhania): Assert details of the error once exposed in
        // `ParseArgsError`.
        assert!(<Args as crate::request::Args>::from_proto(args_proto).is_err());
    }

    #[test]
    fn args_from_proto_args_unsigned_excessive() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());

        let mut arg_quux = rrg_proto::execute_signed_command::command::Arg::new();
        arg_quux.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_quux);

        let mut arg_norf = rrg_proto::execute_signed_command::command::Arg::new();
        arg_norf.set_unsigned_allowed(true);
        command_proto.mut_args().push(arg_norf);

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_args().push(String::from("quux"));
        args_proto.mut_unsigned_args().push(String::from("norf"));
        args_proto.mut_unsigned_args().push(String::from("thud"));

        // TODO(@panhania): Assert details of the error once exposed in
        // `ParseArgsError`.
        assert!(<Args as crate::request::Args>::from_proto(args_proto).is_err());
    }

    #[test]
    fn args_from_proto_env_signed() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());
        command_proto.mut_env_signed().insert("FOO".to_owned(), "quux".to_owned());
        command_proto.mut_env_signed().insert("BAR".to_owned(), "thud".to_owned());

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);

        let args = <Args as crate::request::Args>::from_proto(args_proto)
            .unwrap();
        assert_eq!(args.path, std::path::Path::new("/foo/bar"));
        assert_eq!(args.env["FOO"], "quux");
        assert_eq!(args.env["BAR"], "thud");
    }

    #[test]
    fn args_from_proto_env_unsigned() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());
        command_proto.mut_env_unsigned_allowed().push("FOO".to_owned());
        command_proto.mut_env_unsigned_allowed().push("BAR".to_owned());

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_env().insert("FOO".to_owned(), "quux".to_owned());
        args_proto.mut_unsigned_env().insert("BAR".to_owned(), "thud".to_owned());

        let args = <Args as crate::request::Args>::from_proto(args_proto)
            .unwrap();
        assert_eq!(args.path, std::path::Path::new("/foo/bar"));
        assert_eq!(args.env["FOO"], "quux");
        assert_eq!(args.env["BAR"], "thud");
    }

    #[test]
    fn args_from_proto_env_unsigned_unallowed() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());
        command_proto.mut_env_unsigned_allowed().push("FOO".to_owned());

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_env().insert("FOO".to_owned(), "quux".to_owned());
        args_proto.mut_unsigned_env().insert("BAR".to_owned(), "thud".to_owned());

        // TODO(@panhania): Assert details of the error once exposed in
        // `ParseArgsError`.
        assert!(<Args as crate::request::Args>::from_proto(args_proto).is_err());
    }

    #[test]
    fn args_from_proto_env_unsigned_dup() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let mut command_proto = rrg_proto::execute_signed_command::Command::new();
        command_proto.mut_path().set_raw_bytes(b"/foo/bar".into());
        command_proto.mut_env_signed().insert("FOO".to_owned(), "quux".to_owned());
        command_proto.mut_env_unsigned_allowed().push("FOO".to_owned());

        use protobuf::Message as _;
        let command_bytes = command_proto.write_to_bytes()
            .unwrap();

        let mut args_proto = rrg_proto::execute_signed_command::Args::new();
        args_proto.set_command_ed25519_signature(signing_key.sign(&command_bytes).to_vec());
        args_proto.set_command(command_bytes);
        args_proto.mut_unsigned_env().insert("FOO".to_owned(), "thud".to_owned());

        // TODO(@panhania): Assert details of the error once exposed in
        // `ParseArgsError`.
        assert!(<Args as crate::request::Args>::from_proto(args_proto).is_err());
    }

    fn sha256(content: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;

        let mut sha256 = sha2::Sha256::new();
        sha256.update(content);
        sha256.finalize()
            .into()
    }
}

#[cfg(test)]
#[cfg(feature = "action-execute_signed_command-preverified")]
mod tests {
    use super::*;

    // We just want to test preverification logic so we stick to Unix to keep
    // things simple and be able to rely on the `echo` command.
    #[cfg(target_family = "unix")]
    #[test]
    fn handle_all_preverified() {
        use protobuf::Message as _;

        let mut commands = rrg_proto::execute_signed_command::CommandList::parse_from_bytes({
            include_bytes!(env!("RRG_EXECUTE_SIGNED_COMMAND_PREVERIFIED"))
        }).unwrap();

        for raw_command in commands.take_commands() {
            let args = Args {
                raw_command,
                // In this test we use real raw preverified commands but only to
                // ensure that the verification lets it through. For actual exe-
                // ecution we just run `echo` (as this is safe and preverified
                // commands could have some dangerous stuff in there).
                path: "echo".into(),
                args: ["foo"]
                    .map(CommandArg::literal).into(),
                env: std::collections::HashMap::new(),
                // Again, we provide a signature of just 0. This should not pass
                // the normal verification but we want to test that it is not
                // actually verified.
                ed25519_signature: ed25519_dalek::Signature::from_bytes({
                    &[0; ed25519_dalek::Signature::BYTE_SIZE]
                }),
                stdin: Vec::from(b""),
                timeout: std::time::Duration::from_secs(5),
            };

            let mut session = crate::session::FakeSession::new();
            handle(&mut session, args).unwrap();

            assert_eq!(session.reply_count(), 1);

            let item = session.reply::<Item>(0);
            assert!(item.exit_status.success());
            assert_eq!(item.stdout, b"foo\n");
            assert_eq!(item.stderr, b"");
        }
    }

    #[test]
    fn handle_unverified() {
        use protobuf::Message as _;

        let mut command = rrg_proto::execute_signed_command::Command::new();
        command.mut_path().set_raw_bytes(b"/usr/sbin/iamnotverified".to_vec());

        let args = Args {
            raw_command: command.write_to_bytes().unwrap(),
            path: "/usr/sbin/iamnotverified".into(),
            args: vec![],
            env: std::collections::HashMap::new(),
            ed25519_signature: ed25519_dalek::Signature::from_bytes({
                &[0; ed25519_dalek::Signature::BYTE_SIZE]
            }),
            stdin: Vec::from(b""),
            timeout: std::time::Duration::from_secs(5),
        };

        let mut session = crate::session::FakeSession::new();
        assert!(handle(&mut session, args).is_err());
    }
}
