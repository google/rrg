// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use std::{collections::HashMap, env, io::{Read, Write}, process::{Command, ExitStatus}};

use protobuf::Message;

// TODO(s-westphal): Check and update max size.
const MAX_OUTPUT_SIZE: usize = 4048;
const COMMAND_EXECUTION_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Arguments of the `execute_signed_command` action.
pub struct Args {
    raw_command: Vec<u8>,
    command: rrg_proto::execute_signed_command::SignedCommand,
    stdin: Stdin,
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

enum Stdin {
    NONE,
    UNSIGNED(Vec<u8>),
    SIGNED(Vec<u8>),
}


/// Handles invocations of the `execute_signed_command` action.
pub fn handle<S>(session: &mut S, mut args: Args) -> crate::session::Result<()>
where
    S: crate::session::Session,
{
    match session.args().command_verification_key {
        Some(key) => key.verify_strict(&args.raw_command, &args.ed25519_signature)
            .map_err(crate::session::Error::action)?,
        None => panic!("missing verification key for signed command"),
    };

    let command_path = &std::path::PathBuf::try_from(args.command.take_path())
        .map_err(crate::session::Error::action)?;

    for (key, value) in env::vars() {
        println!("{key}: {value}");
    }
    // For calling `cmd /C <command>` in windows, C:\Windows\System32
    // needs to be on the PATH, otherwise <command> is not found.
    // In Windows ci tests on Github the PATH env var is not capitalized 🤔.
    let filtered_env : HashMap<String, String> =
        env::vars().filter(|&(ref k, _)|
            k == "Path" || k == "PATH"
        ).collect();

    let mut command_process = Command::new(command_path)
        .stdin(std::process::Stdio::piped())
        .args(args.command.take_args())
        .env_clear()
        .envs(filtered_env)
        .envs(args.command.take_env())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(crate::session::Error::action)?;

    let command_start_time = std::time::SystemTime::now();

    let mut command_stdin = match command_process.stdin.take() {
        Some(command_stdin) => command_stdin,
        None => panic!("command stdin pipe should not be None")
    };
    let handle = std::thread::spawn(move || {
        match args.stdin {
            Stdin::SIGNED(signed) => command_stdin.write(&signed[..]).expect("Failed to write to stdin"),
            Stdin::UNSIGNED(unsigned) => command_stdin.write(&unsigned[..]).expect("Failed to write to stdin"),
            Stdin::NONE => 0,
        };
    });

    // TODO(s-westphal): join returns a `Box<dyn std::any::Any + Send>`
    // error which cannot be passed to crate:session:Error::action.
    let _ = handle.join().unwrap();

    while std::time::SystemTime::now().duration_since(command_start_time).unwrap() < args.timeout {
        match command_process.try_wait() {
            Ok(None) => {
                log::debug!("command not completed, waiting {:?}", COMMAND_EXECUTION_CHECK_INTERVAL);
                std::thread::sleep(COMMAND_EXECUTION_CHECK_INTERVAL);
            }
            _ => break,
        }
    }
    // Either the process has exited, then kill doesn't do anything,
    // or we kill the process.
    command_process.kill().map_err(crate::session::Error::action)?;

    let exit_status = command_process.wait()
        .map_err(crate::session::Error::action)?;

    let mut stdout = Vec::<u8>::new();
    let length_stdout = match command_process.stdout.take() {
        Some(mut process_stdout) => {
            process_stdout.read_to_end(&mut stdout).map_err(crate::session::Error::action)?
        }
        None => 0,
    };
    let truncated_stdout = length_stdout > MAX_OUTPUT_SIZE;
    if truncated_stdout {
        stdout.truncate(MAX_OUTPUT_SIZE);
    };

    let mut stderr = Vec::<u8>::new();
    let length_stderr = match command_process.stderr.take() {
        Some(mut process_stderr) => {
            process_stderr.read_to_end(&mut stderr).map_err(crate::session::Error::action)?
        }
        None => 0,
    };
    let truncated_stderr = length_stderr > MAX_OUTPUT_SIZE;
    if truncated_stderr {
        stderr.truncate(MAX_OUTPUT_SIZE);
    };

    session.reply(Item{
        exit_status,
        stdout,
        stderr,
        truncated_stdout,
        truncated_stderr,
    })?;

    Ok(())
}

impl crate::request::Args for Args {

    type Proto = rrg_proto::execute_signed_command::Args;

    fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
        use crate::request::ParseArgsError;

        let raw_signature= proto.take_command_ed25519_signature();

        let ed25519_signature = ed25519_dalek::Signature::try_from(&raw_signature[..])
            .map_err(|error| ParseArgsError::invalid_field("command_ed25519_signature", error))?;

        let raw_command = proto.take_command();
        let mut command = rrg_proto::execute_signed_command::SignedCommand::parse_from_bytes(&raw_command)
            .map_err(|error| ParseArgsError::invalid_field("command", error))?;


        let stdin: Stdin;
        if command.has_signed_stdin() {
            stdin = Stdin::SIGNED(command.take_signed_stdin());
        } else if command.unsigned_stdin() && !proto.unsigned_stdin.is_empty() {
            stdin = Stdin::UNSIGNED(proto.take_unsigned_stdin());
        } else {
            stdin = Stdin::NONE
        }

        let timeout = std::time::Duration::try_from(proto.take_timeout())
            .map_err(|error| ParseArgsError::invalid_field("command", error))?;

        Ok(Args {
            raw_command,
            command,
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
            use std::os::unix::process::ExitStatusExt;

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

    #[test]
    fn test_args() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();

        #[cfg(target_family = "unix")] {
            command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("echo")).unwrap());
        }
        #[cfg(target_os = "windows")] {
            command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("cmd")).unwrap());
            command.args.push(String::from("/C"));
            command.args.push(String::from("echo"));
        }
        command.args.push(String::from("Hello,"));
        command.args.push(String::from("world!"));

        let raw_command = command.write_to_bytes().unwrap();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            command,
            ed25519_signature,
            stdin: Stdin::NONE,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
        assert!(item.stderr.is_empty());
        #[cfg(target_family = "unix")]
        assert_eq!(String::from_utf8_lossy(&item.stdout), format!("Hello, world!\n"));
        #[cfg(target_os = "windows")]
        assert_eq!(String::from_utf8_lossy(&item.stdout), format!("Hello, world!\r\n"));
        assert!(item.exit_status.success())
    }

    #[test]
    fn test_signed_stdin() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let stdin = Stdin::SIGNED(Vec::<u8>::from("Hello, world!"));

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();

        #[cfg(target_family = "unix")]
        command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("cat")).unwrap());

        #[cfg(target_os = "windows")] {
            command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("cmd")).unwrap());
            command.args.push(String::from("/C"));
            command.args.push(String::from("findstr ."));
        }

        let raw_command = command.write_to_bytes().unwrap();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            command,
            ed25519_signature,
            stdin,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        #[cfg(target_family = "unix")]
        assert_eq!(String::from_utf8_lossy(&item.stdout), format!("Hello, world!"));
        #[cfg(target_os = "windows")]
        assert_eq!(String::from_utf8_lossy(&item.stdout), format!("Hello, world!\r\n"));
        assert!(item.stderr.is_empty());
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
        assert!(item.exit_status.success());
    }

    #[test]
    fn test_unsigned_stdin() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let stdin = Stdin::UNSIGNED(Vec::<u8>::from("Hello, world!"));

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();
        command.set_unsigned_stdin(true);

        #[cfg(target_family = "unix")]
        command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("cat")).unwrap());

        #[cfg(target_os = "windows")] {
            command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("cmd")).unwrap());
            command.args.push(String::from("/C"));
            command.args.push(String::from("findstr ."));
        }

        let raw_command = command.write_to_bytes().unwrap();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            command,
            ed25519_signature,
            stdin,
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        #[cfg(target_family = "unix")]
        assert_eq!(String::from_utf8_lossy(&item.stdout), format!("Hello, world!"));
        #[cfg(target_os = "windows")]
        assert_eq!(String::from_utf8_lossy(&item.stdout), format!("Hello, world!\r\n"));
        assert!(item.stderr.is_empty());
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
        assert!(item.exit_status.success());
    }

    #[test]
    fn test_env() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();
        command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("printenv")).unwrap());
        command.env.insert(String::from("MY_ENV_VAR"), String::from("Hello, world!"));

        let raw_command = command.write_to_bytes().unwrap();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            command,
            ed25519_signature,
            stdin: Stdin::NONE,
            timeout: std::time::Duration::from_secs(5),
        };
        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(String::from_utf8_lossy(&item.stdout).find("MY_ENV_VAR=Hello, world!").is_some());
        assert!(item.stderr.is_empty());
        assert!(!item.truncated_stdout);
        assert!(!item.truncated_stderr);
        assert!(item.exit_status.success());
    }

    #[test]
    fn test_invalid_signature() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();
        command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("ls")).unwrap());

        let raw_command = command.write_to_bytes().unwrap();

        let invalid_signature_bytes: [u8; 64] = [4_u8; 64]; //  random bytes.
        let invalid_signature = ed25519_dalek::Signature::from_bytes(&invalid_signature_bytes);

        let args = Args {
            raw_command,
            command,
            ed25519_signature: invalid_signature,
            stdin: Stdin::NONE,
            timeout: std::time::Duration::from_secs(5),
        };

        let _ = handle(&mut session, args).is_err();
    }

    #[test]
    fn test_truncated_output() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();

        #[cfg(target_family = "unix")] 
        command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("echo")).unwrap());
        
        #[cfg(target_os = "windows")] {
            command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("cmd")).unwrap());
            command.args.push(String::from("/C"));
            command.args.push(String::from("echo"));
        }

        command.args.push("A".repeat(MAX_OUTPUT_SIZE) + "truncated");

        let raw_command = command.write_to_bytes().unwrap();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            command,
            ed25519_signature,
            stdin: Stdin::NONE,
            timeout: std::time::Duration::from_secs(5),
        };

        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert_eq!(String::from_utf8_lossy(&item.stdout), "A".repeat(MAX_OUTPUT_SIZE));
        assert!(item.stderr.is_empty());
        assert!(item.truncated_stdout);
        assert!(!item.truncated_stderr);
        assert!(item.exit_status.success());
    }

    #[test]
    fn test_timeout() {
        let timeout = std::time::Duration::from_secs(5);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session = prepare_session(signing_key.verifying_key());

        let mut command = rrg_proto::execute_signed_command::SignedCommand::new();
        command.set_path(rrg_proto::fs::Path::try_from(PathBuf::from("sleep")).unwrap());
        command.args.push((timeout.as_secs() + 1).to_string());

        let raw_command = command.write_to_bytes().unwrap();
        let ed25519_signature = signing_key.sign(&raw_command);

        let args = Args {
            raw_command,
            command,
            ed25519_signature,
            stdin: Stdin::NONE,
            timeout,
        };

        handle(&mut session, args).unwrap();
        let item = session.reply::<Item>(0);

        assert!(item.stderr.is_empty());
        assert!(item.stdout.is_empty());
        assert!(!item.exit_status.success());
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::process::ExitStatusExt;

            assert_eq!(item.exit_status.signal(), Some(9)); // killed
        }
    }
}