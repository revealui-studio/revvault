use std::io::{self, IsTerminal, Read};

use clap::Args;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use zeroize::Zeroizing;

const SERVICE_INPUT_LIMIT: usize = 64 * 1024;

#[derive(Args)]
pub struct SetArgs {
    /// Create one approved service secret in its independent fixed store (root only).
    #[arg(long, value_name = "UID", conflicts_with_all = ["force", "multiline", "value", "operation_id", "expected_current_sha256", "expected_absent"])]
    pub service_uid: Option<u32>,
    /// Immutable nonsecret request descriptor, mandatory for service imports.
    #[arg(long, value_name = "FILE", requires = "service_uid")]
    pub service_request: Option<std::path::PathBuf>,
    /// Secret path (e.g., "credentials/stripe/secret-key")
    pub path: String,

    /// Overwrite existing secret without error
    #[arg(short, long)]
    pub force: bool,

    /// Prompt for multi-line input (visible) instead of a single hidden line
    #[arg(short, long)]
    pub multiline: bool,

    /// Literal value (discouraged for credentials — leaks to shell history)
    #[arg(long)]
    pub value: Option<String>,

    /// Stable UUID for an idempotent conditional single-leaf write
    #[arg(long, requires = "expected", conflicts_with_all = ["force", "value", "multiline"])]
    pub operation_id: Option<String>,

    /// SHA256 of the exact current decrypted bytes
    #[arg(long, group = "expected", requires = "operation_id")]
    pub expected_current_sha256: Option<String>,

    /// Require that the secret does not exist
    #[arg(long, group = "expected", requires = "operation_id")]
    pub expected_absent: bool,

    /// Accepted for compatibility. The byte-count line is always printed.
    #[arg(long)]
    pub verbose: bool,
}

/// Success line for `set` and `edit`. Byte length is the exact stored length.
/// Confirmation includes only byte length and logical path, never secret content.
pub(crate) fn stored_confirmation(path: &str, stored: &str) -> String {
    format!("stored {} bytes at {path}", stored.len())
}

pub fn run(
    args: SetArgs,
    json_output: bool,
    deadline: Option<&revvault_core::service::receiver::ServiceReceiverDeadline>,
) -> anyhow::Result<()> {
    if let Some(uid) = args.service_uid {
        use revvault_core::service::receiver::{ServiceInvocation, ServiceMutationGuard};
        let request = args
            .service_request
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
        let deadline =
            deadline.ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
        let guard = ServiceMutationGuard::begin(
            deadline,
            request,
            ServiceInvocation::Import {
                uid,
                selector: args.path.clone(),
            },
        )?;
        let input = read_service_secret(io::stdin().lock(), io::stdin().is_terminal())?;
        let stored_bytes = input.expose_secret().len();
        guard.execute(Some(input))?;
        eprintln!("stored {stored_bytes} bytes at {}", args.path);
        if json_output {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "status": "stored", "path": args.path, "bytes": stored_bytes,
                }))?
            );
        }
        return Ok(());
    }
    let store = super::open_store()?;
    let tty = io::stdin().is_terminal();

    if args.value.is_some() {
        eprintln!(
            "warning: --value exposes the secret in shell history; prefer a prompt or piped stdin"
        );
    }

    if let Some(ref operation_id) = args.operation_id {
        if tty {
            anyhow::bail!("conditional writes require piped stdin");
        }
        let mut desired = Vec::new();
        io::stdin().read_to_end(&mut desired)?;
        if desired.is_empty() {
            anyhow::bail!("no input provided on stdin");
        }
        let expected = if args.expected_absent {
            revvault_core::store::ExpectedCurrent::Absent
        } else {
            revvault_core::store::ExpectedCurrent::Sha256(
                args.expected_current_sha256.clone().unwrap(),
            )
        };
        let receipt = store.compare_and_upsert(&args.path, expected, &desired, operation_id)?;
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }

    let input = SecretString::from(read_secret(&args, tty)?);
    let trimmed = input.expose_secret().trim();

    if trimmed.is_empty() {
        if tty && args.value.is_none() {
            anyhow::bail!("no secret entered");
        }
        anyhow::bail!("no input provided on stdin");
    }

    if args.force {
        store.upsert(&args.path, trimmed.as_bytes())?;
    } else {
        store.set(&args.path, trimmed.as_bytes())?;
    }

    let _ = args.verbose;
    eprintln!("{}", stored_confirmation(&args.path, trimmed));
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "stored",
                "path": args.path,
                "bytes": trimmed.len(),
            }))?
        );
    }

    Ok(())
}

fn read_service_secret(mut input: impl Read, terminal: bool) -> anyhow::Result<SecretString> {
    let denied = || anyhow::anyhow!("revvault_service_import_input_denied");
    if terminal {
        return Err(denied());
    }
    // Allocate once, including the over-limit sentinel. Zeroizing owns the
    // buffer before the first read, including partial-read/error exits.
    let mut bytes = Zeroizing::new(vec![0_u8; SERVICE_INPUT_LIMIT + 1]);
    let mut count = 0;
    loop {
        match input.read(&mut bytes[count..]) {
            Ok(0) => break,
            Ok(read) => {
                count += read;
                if count > SERVICE_INPUT_LIMIT {
                    return Err(denied());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(denied()),
        }
    }
    let value = std::str::from_utf8(&bytes[..count]).map_err(|_| denied())?;
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        return Err(denied());
    }
    Ok(SecretString::from(value.to_owned()))
}

/// Read the secret value: `--value`, a hidden one-line prompt on a terminal,
/// or raw stdin-to-EOF when piped.
fn read_secret(args: &SetArgs, tty: bool) -> anyhow::Result<String> {
    if let Some(value) = &args.value {
        return Ok(value.clone());
    }

    if !tty {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }

    let overwrite = if args.force { "yes" } else { "no" };
    eprintln!("Set {} (overwrite: {overwrite})", args.path);

    if args.multiline {
        eprintln!("Enter multi-line secret, then Ctrl-D to submit (Ctrl-C to cancel).");
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }

    eprintln!("Enter value, then Enter to submit (Ctrl-C to cancel).");
    eprintln!("Input will not be echoed.");
    eprint!("> ");
    Ok(rpassword::read_password()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_input_preserves_multiline_content_and_accepts_exact_limit() {
        let secret = read_service_secret(&b" \nfirst\nsecond\n "[..], false).unwrap();
        assert_eq!(secret.expose_secret(), "first\nsecond");
        let largest = vec![b'x'; SERVICE_INPUT_LIMIT];
        assert_eq!(
            read_service_secret(largest.as_slice(), false)
                .unwrap()
                .expose_secret()
                .len(),
            SERVICE_INPUT_LIMIT
        );
    }

    #[test]
    fn service_input_rejects_invalid_and_oversized_streams_without_echoing_input() {
        for bytes in [
            vec![],
            b" \n\t".to_vec(),
            vec![0xff],
            b"synthetic-secret\0suffix".to_vec(),
            vec![b'x'; SERVICE_INPUT_LIMIT + 1],
        ] {
            let error = read_service_secret(bytes.as_slice(), false).err().unwrap();
            assert_eq!(error.to_string(), "revvault_service_import_input_denied");
        }
    }

    struct FaultingInput {
        reads: usize,
    }

    impl Read for FaultingInput {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            match self.reads {
                1 => Err(io::ErrorKind::Interrupted.into()),
                2 => {
                    bytes[..6].copy_from_slice(b"secret");
                    Ok(6)
                }
                _ => Err(io::Error::other("synthetic-secret-in-reader-error")),
            }
        }
    }

    #[test]
    fn service_input_closes_partial_read_errors_and_denies_terminal_before_reading() {
        let mut input = FaultingInput { reads: 0 };
        let error = read_service_secret(&mut input, true).err().unwrap();
        assert_eq!(input.reads, 0);
        assert_eq!(error.to_string(), "revvault_service_import_input_denied");
        let error = read_service_secret(&mut input, false).err().unwrap();
        assert_eq!(input.reads, 3);
        assert_eq!(error.to_string(), "revvault_service_import_input_denied");
    }
}
