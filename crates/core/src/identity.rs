use std::fs;
use std::path::Path;

use age::x25519;

use crate::error::{Result, RevvaultError};

/// Loaded age identity (private key) used for decryption.
pub struct Identity {
    identities: Vec<x25519::Identity>,
}

impl Identity {
    /// Load age identities from a key file.
    ///
    /// The file can contain multiple identity lines (one per line),
    /// plus comment lines starting with `#`.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = zeroize::Zeroizing::new(
            fs::read_to_string(path)
                .map_err(|_| RevvaultError::IdentityNotFound(path.to_path_buf()))?,
        );
        Self::from_text(&contents)
    }

    /// Same strict loader for trusted in-memory recovery input; no key file
    /// staging or separate service-only identity parser.
    pub(crate) fn from_text(contents: &str) -> Result<Self> {
        let identities: Vec<x25519::Identity> = contents
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .map(|line| line.trim().parse::<x25519::Identity>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                RevvaultError::DecryptionFailed("invalid age identity in key file".into())
            })?;

        if identities.is_empty() {
            return Err(RevvaultError::DecryptionFailed(
                "no valid age identities found in key file".into(),
            ));
        }

        Ok(Self { identities })
    }

    /// Get a reference to the loaded identities for decryption.
    pub fn as_identities(&self) -> &[x25519::Identity] {
        &self.identities
    }

    /// Get the public key (recipient) for the first identity.
    pub fn default_recipient(&self) -> x25519::Recipient {
        self.identities[0].to_public()
    }

    /// Create an identity from pre-generated keys (for testing).
    #[cfg(test)]
    pub fn from_generated(identities: Vec<x25519::Identity>) -> Self {
        Self { identities }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn load_identity_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");

        // Generate a test identity
        let identity = x25519::Identity::generate();
        let secret_key = identity.to_string();

        fs::write(
            &key_file,
            format!(
                "# created: 2024-01-01\n# public key: {}\n{}\n",
                identity.to_public(),
                secret_key.expose_secret()
            ),
        )
        .unwrap();

        let loaded = Identity::from_file(&key_file).unwrap();
        assert_eq!(loaded.as_identities().len(), 1);
    }

    #[test]
    fn from_file_missing_path_fails() {
        let result = Identity::from_file(Path::new("/nonexistent/path/keys.txt"));
        assert!(matches!(result, Err(RevvaultError::IdentityNotFound(_))));
    }

    #[test]
    fn from_file_empty_contents_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");
        fs::write(&key_file, "").unwrap();

        let result = Identity::from_file(&key_file);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn from_file_only_comments_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");
        fs::write(&key_file, "# created: 2024-01-01\n# public key: age1abc\n").unwrap();

        let result = Identity::from_file(&key_file);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn from_file_malformed_identity_string_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");
        fs::write(&key_file, "not-a-valid-age-identity-string\n").unwrap();

        let result = Identity::from_file(&key_file);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn from_file_wrong_key_type_rejects_recipient_string() {
        // A recipient (public key) is a different key type than an identity
        // (private key); it must not silently parse as an identity.
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");
        let generated = x25519::Identity::generate();
        fs::write(&key_file, format!("{}\n", generated.to_public())).unwrap();

        let result = Identity::from_file(&key_file);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn from_file_rejects_malformed_lines_even_with_valid_identity() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("keys.txt");
        let valid = x25519::Identity::generate();

        fs::write(
            &key_file,
            format!(
                "garbage-line\n{}\nanother-garbage-line\n",
                valid.to_string().expose_secret()
            ),
        )
        .unwrap();

        assert!(Identity::from_file(&key_file).is_err());
    }

    #[test]
    fn default_recipient_matches_first_identity() {
        let id = x25519::Identity::generate();
        let expected = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        assert_eq!(
            identity.default_recipient().to_string(),
            expected.to_string()
        );
    }
}
