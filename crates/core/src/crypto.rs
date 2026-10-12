use std::io::{Read, Write};

use age::x25519;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Result, RevvaultError};
use crate::identity::Identity;

/// Encrypt plaintext bytes to one or more age recipients.
pub fn encrypt(plaintext: &[u8], recipients: &[x25519::Recipient]) -> Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| RevvaultError::EncryptionFailed(e.to_string()))?;

    Ok(encrypted)
}

/// Decrypt an age-encrypted blob using the provided identity.
pub fn decrypt(ciphertext: &[u8], identity: &Identity) -> Result<SecretString> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| RevvaultError::DecryptionFailed(e.to_string()))?;

    if decryptor.is_scrypt() {
        return Err(RevvaultError::DecryptionFailed(
            "passphrase-encrypted files not supported".into(),
        ));
    }

    let mut decrypted = zeroize::Zeroizing::new(Vec::new());
    let mut reader = decryptor
        .decrypt(
            identity
                .as_identities()
                .iter()
                .map(|i| i as &dyn age::Identity),
        )
        .map_err(|e: age::DecryptError| RevvaultError::DecryptionFailed(e.to_string()))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e: std::io::Error| RevvaultError::DecryptionFailed(e.to_string()))?;

    let plaintext = std::str::from_utf8(&decrypted)
        .map_err(|e| RevvaultError::DecryptionFailed(e.to_string()))?
        .to_owned();

    Ok(SecretString::from(plaintext))
}

/// Load recipients from a `.age-recipients` file.
pub fn load_recipients(path: &std::path::Path) -> Result<Vec<x25519::Recipient>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|_| RevvaultError::RecipientsNotFound(path.to_path_buf()))?;

    parse_recipients(&contents).map_err(|_| RevvaultError::RecipientsNotFound(path.to_path_buf()))
}

/// Shared strict recipient parser for files and independently encrypted
/// service checkpoint contents.
pub(crate) fn parse_recipients(contents: &str) -> Result<Vec<x25519::Recipient>> {
    let recipients: Vec<x25519::Recipient> = contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| line.trim().parse::<x25519::Recipient>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| RevvaultError::DecryptionFailed("invalid age recipients".into()))?;

    if recipients.is_empty() {
        return Err(RevvaultError::DecryptionFailed("no age recipients".into()));
    }

    Ok(recipients)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let plaintext = b"sk_live_test_secret_key_12345";
        let ciphertext = encrypt(plaintext, &[recipient]).unwrap();

        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt(&ciphertext, &identity).unwrap();
        assert_eq!(decrypted.expose_secret(), "sk_live_test_secret_key_12345");
    }

    #[test]
    fn decrypt_with_wrong_identity_fails() {
        let owner = x25519::Identity::generate();
        let recipient = owner.to_public();
        let intruder = Identity::from_generated(vec![x25519::Identity::generate()]);

        let ciphertext = encrypt(b"top secret", &[recipient]).unwrap();

        let result = decrypt(&ciphertext, &intruder);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn decrypt_tampered_ciphertext_start_fails() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let mut ciphertext = encrypt(b"tamper me", &[recipient]).unwrap();
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&ciphertext, &identity);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_middle_fails() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let mut ciphertext = encrypt(b"tamper me in the middle please", &[recipient]).unwrap();
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;

        let result = decrypt(&ciphertext, &identity);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_end_fails() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let mut ciphertext = encrypt(b"tamper me at the end", &[recipient]).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = decrypt(&ciphertext, &identity);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let ciphertext = encrypt(b"truncate me", &[recipient]).unwrap();
        let truncated = &ciphertext[..ciphertext.len() / 2];

        let result = decrypt(truncated, &identity);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn decrypt_empty_input_fails() {
        let id = x25519::Identity::generate();
        let identity = Identity::from_generated(vec![id]);

        let result = decrypt(&[], &identity);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn decrypt_garbage_non_age_input_fails() {
        let id = x25519::Identity::generate();
        let identity = Identity::from_generated(vec![id]);

        let garbage = b"this is not an age file at all, just plain text bytes";
        let result = decrypt(garbage, &identity);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let id = x25519::Identity::generate();
        let recipient = id.to_public();
        let identity = Identity::from_generated(vec![id]);

        let ciphertext = encrypt(b"", &[recipient]).unwrap();
        let decrypted = decrypt(&ciphertext, &identity).unwrap();
        assert_eq!(decrypted.expose_secret(), "");
    }

    #[test]
    fn multi_recipient_encrypt_decrypt_by_either_recipient() {
        let id_a = x25519::Identity::generate();
        let id_b = x25519::Identity::generate();
        let recipients = vec![id_a.to_public(), id_b.to_public()];

        let ciphertext = encrypt(b"shared secret", &recipients).unwrap();

        let identity_a = Identity::from_generated(vec![id_a]);
        let decrypted_a = decrypt(&ciphertext, &identity_a).unwrap();
        assert_eq!(decrypted_a.expose_secret(), "shared secret");

        let identity_b = Identity::from_generated(vec![id_b]);
        let decrypted_b = decrypt(&ciphertext, &identity_b).unwrap();
        assert_eq!(decrypted_b.expose_secret(), "shared secret");
    }

    #[test]
    fn multi_recipient_excluded_identity_fails() {
        let id_a = x25519::Identity::generate();
        let id_b = x25519::Identity::generate();
        let outsider = x25519::Identity::generate();
        let recipients = vec![id_a.to_public(), id_b.to_public()];

        let ciphertext = encrypt(b"shared secret", &recipients).unwrap();

        let outsider_identity = Identity::from_generated(vec![outsider]);
        let result = decrypt(&ciphertext, &outsider_identity);
        assert!(matches!(result, Err(RevvaultError::DecryptionFailed(_))));
    }

    #[test]
    fn load_recipients_missing_file_fails() {
        let result = load_recipients(std::path::Path::new("/nonexistent/path/.age-recipients"));
        assert!(matches!(result, Err(RevvaultError::RecipientsNotFound(_))));
    }

    #[test]
    fn load_recipients_empty_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".age-recipients");
        std::fs::write(&path, "# just a comment\n\n").unwrap();

        let result = load_recipients(&path);
        assert!(matches!(result, Err(RevvaultError::RecipientsNotFound(_))));
    }

    #[test]
    fn load_recipients_rejects_malformed_lines_even_with_valid_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".age-recipients");
        let id = x25519::Identity::generate();
        std::fs::write(
            &path,
            format!("not-a-valid-recipient\n{}\n", id.to_public()),
        )
        .unwrap();

        assert!(load_recipients(&path).is_err());
    }

    #[test]
    fn key_files_accept_comments_blank_lines_and_explicit_valid_sharing() {
        let dir = tempfile::tempdir().unwrap();
        let first = x25519::Identity::generate();
        let second = x25519::Identity::generate();
        let recipients_path = dir.path().join(".age-recipients");
        let identity_path = dir.path().join("identity.txt");
        std::fs::write(
            &recipients_path,
            format!(
                "# recipients\n\n{}\n  {}\n",
                first.to_public(),
                second.to_public()
            ),
        )
        .unwrap();
        std::fs::write(
            &identity_path,
            format!(
                "# identities\n\n{}\n  {}\n",
                first.to_string().expose_secret(),
                second.to_string().expose_secret()
            ),
        )
        .unwrap();
        let recipients = load_recipients(&recipients_path).unwrap();
        assert_eq!(recipients.len(), 2);
        let identity = Identity::from_file(&identity_path).unwrap();
        assert_eq!(identity.as_identities().len(), 2);
        let ciphertext = encrypt(b"synthetic-shared-secret", &recipients).unwrap();
        assert_eq!(
            decrypt(&ciphertext, &identity).unwrap().expose_secret(),
            "synthetic-shared-secret"
        );
    }
}
