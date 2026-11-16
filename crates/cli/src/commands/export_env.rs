use clap::{Args, ValueEnum};
use revvault_core::sync::shape;
use secrecy::ExposeSecret;
use serde_json::json;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum EnvFormat {
    #[default]
    Auto,
    Env,
    Scalar,
}

#[derive(Args)]
pub struct ExportEnvArgs {
    /// Secret path (multiline secrets become KEY=VALUE lines)
    pub path: String,

    /// Select env assignments or a scalar value; auto recognizes assignment bundles.
    #[arg(long, value_enum, default_value = "auto")]
    pub format: EnvFormat,

    /// Refuse to export any value that classifies as a PKCS#8 private key
    /// (GAP-260 P2-2). Use for verify-only namespaces such as
    /// `revealui/env/license`. When a private key is present in the secret
    /// payload, exit nonzero instead of emitting it.
    #[arg(long = "public-only")]
    pub public_only: bool,
}

/// Shell-quote a value using single quotes, escaping any embedded single quotes.
/// Output is safe for use with `eval` regardless of special characters in the value.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Parse the secret into key-value pairs, used by both output modes.
fn valid_env_name(name: &str) -> bool {
    let mut chars = name.bytes();
    matches!(chars.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn parse_env_vars(
    path: &str,
    value: &str,
    format: EnvFormat,
) -> anyhow::Result<Vec<(String, String)>> {
    let trimmed = value.trim();
    // Padded scalar tokens and PEMs are values, not assignment bundles.
    let padded_scalar = !trimmed.contains('\n')
        && trimmed.ends_with('=')
        && !trimmed.trim_end_matches('=').contains('=');
    let bundle = match format {
        EnvFormat::Env => true,
        EnvFormat::Scalar => false,
        EnvFormat::Auto => {
            !padded_scalar
                && !trimmed.starts_with("-----BEGIN ")
                && value
                    .lines()
                    .any(|line| line.contains('=') && !line.trim_start().starts_with('#'))
                && (trimmed.contains('\n')
                    || trimmed
                        .split_once('=')
                        .is_some_and(|(k, _)| valid_env_name(k)))
        }
    };
    if bundle {
        let mut result = Vec::new();
        let mut lines = value.lines();
        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, val) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid environment assignment"))?;
            anyhow::ensure!(valid_env_name(key), "invalid environment variable name");
            let mut val = val.to_string();
            // PEM bundles store real newlines as well as escaped newlines. Keep
            // the full block as one quoted value, including padded base64 rows.
            if val.starts_with("-----BEGIN ") && val.ends_with("-----") && !val.contains("\\n") {
                let end = val.replacen("BEGIN ", "END ", 1);
                let mut closed = false;
                for continuation in lines.by_ref() {
                    val.push('\n');
                    val.push_str(continuation);
                    if continuation.trim() == end {
                        closed = true;
                        break;
                    }
                }
                anyhow::ensure!(closed, "unterminated PEM environment value");
            }
            result.push((key.to_string(), val));
        }
        Ok(result)
    } else {
        let key = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_uppercase()
            .replace('-', "_");
        anyhow::ensure!(
            valid_env_name(&key),
            "secret path does not produce a valid environment variable name"
        );
        Ok(vec![(key, value.to_string())])
    }
}

/// True when `value` is (or contains) a PEM private key.
///
/// For multiline PEMs stored as a single env value, `shape::classify` sees the
/// full block. For KEY=VALUE bundles, each value is classified independently.
fn is_private_key_value(value: &str) -> bool {
    // Restore literal newlines that vault bundles often store as \n sequences
    // so classify sees a real PEM block (no authored regex).
    let normalized = value.split("\\n").collect::<Vec<_>>().join("\n");
    shape::classify(&normalized) == "pem-private-key"
        || (normalized.contains("BEGIN") && normalized.contains("PRIVATE KEY"))
}

fn refuse_private_keys(vars: &[(String, String)]) -> anyhow::Result<()> {
    let mut offenders: Vec<String> = Vec::new();
    for (key, val) in vars {
        if is_private_key_value(val) {
            offenders.push(key.clone());
        }
    }
    if offenders.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "export-env --public-only refused private-key value(s) for: {}. \
         Use a public-only vault path (e.g. revealui/env/license with SPKI only) \
         or load signing material via with-secrets license-signing \
         (requires REVVAULT_ALLOW_PRIVATE=1).",
        offenders.join(", ")
    );
}

/// Load path → KEY=VALUE pairs (shared with `revvault run`).
pub fn load_env_vars(args: &ExportEnvArgs) -> anyhow::Result<Vec<(String, String)>> {
    let store = super::open_store()?;
    let secret = store.get(&args.path)?;
    let value = secret.expose_secret();
    let vars = parse_env_vars(&args.path, value, args.format)?;
    if args.public_only {
        refuse_private_keys(&vars)?;
    }
    Ok(vars)
}

pub fn run(args: ExportEnvArgs, json_output: bool) -> anyhow::Result<()> {
    // Default output prints `export KEY=value`. Refuse on a TTY under
    // STREAM_SAFE. Piped `eval "$(revvault export-env …)"` is non-TTY.
    super::stream_safe::gate_human_disclosure(false, super::stream_safe::stdout_is_tty())?;

    let vars = load_env_vars(&args)?;

    if json_output {
        let items: Vec<serde_json::Value> = vars
            .iter()
            .map(|(k, v)| json!({"key": k, "value": v}))
            .collect();
        println!("{}", serde_json::to_string(&json!({"variables": items}))?);
        return Ok(());
    }

    for (key, val) in &vars {
        println!("export {}={}", key, shell_quote(val));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shell_exports_reject_untrusted_names() {
        assert!(parse_env_vars("env", "SAFE=one\nX; touch BAD; #=two", EnvFormat::Auto).is_err());
        assert!(parse_env_vars("X;false", "value", EnvFormat::Scalar).is_err());
        assert!(parse_env_vars("env", "X;false=two", EnvFormat::Env).is_err());
    }
    #[test]
    fn multiline_pem_bundle_preserves_base64_padding() {
        let value = "KEY=-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----\nEMPTY=";
        let vars = parse_env_vars("env", value, EnvFormat::Env).unwrap();
        assert_eq!(
            vars[0].1,
            "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----"
        );
        assert_eq!(vars[1], ("EMPTY".into(), "".into()));
    }
    #[test]
    fn scalar_tokens_and_urls_survive_export() {
        for value in [
            "YWJjZA==",
            "https://example.invalid/?key=value",
            "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----",
        ] {
            assert_eq!(
                parse_env_vars("token", value, EnvFormat::Auto).unwrap(),
                vec![("TOKEN".into(), value.into())]
            );
        }
        assert_eq!(
            parse_env_vars("token", "NAME=value", EnvFormat::Scalar).unwrap()[0].1,
            "NAME=value"
        );
        assert_eq!(
            parse_env_vars("env", "EMPTY=", EnvFormat::Env).unwrap()[0],
            ("EMPTY".into(), "".into())
        );
        assert_eq!(
            parse_env_vars("env", "NAME=value", EnvFormat::Auto).unwrap()[0],
            ("NAME".into(), "value".into())
        );
    }
}
