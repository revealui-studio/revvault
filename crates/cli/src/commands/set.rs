use std::io::{self, IsTerminal, Read};

use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct SetArgs {
    /// Root-only, create-only import into one approved service secret.
    #[arg(long, value_name = "UID", conflicts_with_all = [
        "force", "multiline", "value", "operation_id",
        "expected_current_sha256", "expected_absent"
    ])]
    pub service_uid: Option<u32>,
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

pub fn run(args: SetArgs, json_output: bool) -> anyhow::Result<()> {
    let store = if let Some(uid) = args.service_uid {
        revvault_core::PassageStore::open_service_import(uid, &args.path)?
    } else {
        super::open_store()?
    };
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

    let input = read_secret(&args, tty)?;
    let trimmed = input.trim();

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
