//! Group image encryption and decryption functionality for MIP-01
//!
//! This module provides cryptographic operations for group avatar images:
//! - Encryption with ChaCha20-Poly1305 AEAD
//! - Decryption and integrity verification
//! - Deterministic upload keypair derivation for Blossom cleanup
//!
//! The encryption scheme does NOT use AAD for simplicity. Integrity is provided by:
//! 1. SHA256 hash check of encrypted blob (detects substitution)
//! 2. ChaCha20-Poly1305 auth tag (detects tampering/corruption)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use nostr::secp256k1::rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Domain separation label for upload keypair derivation (MIP-01 spec)
const UPLOAD_KEYPAIR_CONTEXT: &[u8] = b"mip01-blossom-upload-v1";

/// Prepared group image data ready for upload to Blossom
#[derive(Debug, Clone)]
pub struct GroupImageUploadPrepared {
    /// Encrypted image data (ready to upload to Blossom)
    pub encrypted_data: Vec<u8>,
    /// SHA256 hash of encrypted data (verify against Blossom response)
    pub encrypted_hash: [u8; 32],
    /// Encryption key (store in extension)
    pub image_key: [u8; 32],
    /// Encryption nonce (store in extension)
    pub image_nonce: [u8; 12],
    /// Derived keypair for Blossom authentication
    pub upload_keypair: nostr::Keys,
    /// Original image size before encryption
    pub original_size: usize,
}

/// Group image encryption result with hash (internal type)
#[derive(Debug, Clone)]
struct GroupImageEncrypted {
    /// The encrypted image data
    encrypted_data: Vec<u8>,
    /// SHA256 hash of encrypted data (for Blossom upload)
    encrypted_hash: [u8; 32],
    /// Encryption key
    image_key: [u8; 32],
    /// Encryption nonce
    image_nonce: [u8; 12],
}

/// Group image encryption info from extension
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupImageEncryptionInfo {
    /// Blossom blob hash (SHA256 of encrypted data)
    pub image_hash: [u8; 32],
    /// Encryption key
    pub image_key: [u8; 32],
    /// Encryption nonce
    pub image_nonce: [u8; 12],
}

/// Errors that can occur during group image operations
#[derive(Debug, thiserror::Error)]
pub enum GroupImageError {
    /// Encryption failed
    #[error("Encryption failed: {reason}")]
    EncryptionFailed {
        /// The reason for encryption failure
        reason: String,
    },

    /// Decryption failed
    #[error("Decryption failed: {reason}")]
    DecryptionFailed {
        /// The reason for decryption failure
        reason: String,
    },

    /// Hash verification failed
    #[error("Hash verification failed: expected {expected}, got {actual}")]
    HashVerificationFailed {
        /// The expected hash value
        expected: String,
        /// The actual hash value
        actual: String,
    },

    /// Upload keypair derivation failed
    #[error("Failed to derive upload keypair: {reason}")]
    KeypairDerivationFailed {
        /// The reason for derivation failure
        reason: String,
    },
}

/// Encrypt group image with random key and nonce
///
/// This is an internal function used by `prepare_group_image_for_upload()`.
/// Users should use `prepare_group_image_for_upload()` instead.
fn encrypt_group_image(image_data: &[u8]) -> Result<GroupImageEncrypted, GroupImageError> {
    // Generate random key and nonce
    let mut rng = OsRng;
    let mut image_key = [0u8; 32];
    let mut image_nonce = [0u8; 12];
    rng.fill_bytes(&mut image_key);
    rng.fill_bytes(&mut image_nonce);

    // Encrypt with ChaCha20-Poly1305 (no AAD per MIP-01 spec)
    let cipher = ChaCha20Poly1305::new_from_slice(&image_key).map_err(|e| {
        GroupImageError::EncryptionFailed {
            reason: format!("Failed to create cipher: {}", e),
        }
    })?;

    let nonce = Nonce::from_slice(&image_nonce);
    let encrypted_data = cipher.encrypt(nonce, image_data).map_err(|e| {
        GroupImageError::EncryptionFailed {
            reason: format!("Encryption failed: {}", e),
        }
    })?;

    // Calculate hash of encrypted data
    let encrypted_hash: [u8; 32] = Sha256::digest(&encrypted_data).into();

    Ok(GroupImageEncrypted {
        encrypted_data,
        encrypted_hash,
        image_key,
        image_nonce,
    })
}

/// Decrypt group image using extension data
///
/// Decrypts the encrypted blob using ChaCha20-Poly1305 AEAD. The auth tag
/// automatically verifies integrity - if tampering occurred, decryption will fail.
///
/// # Arguments
/// * `encrypted_data` - Encrypted blob downloaded from Blossom
/// * `image_key` - Encryption key from group extension
/// * `image_nonce` - Encryption nonce from group extension
///
/// # Returns
/// * Decrypted image bytes
///
/// # Errors
/// * `DecryptionFailed` - If auth tag verification fails (tampering detected)
///
/// # Example
/// ```ignore
/// let extension = mdk.get_group_extension(&group_id)?;
/// if let Some(info) = extension.group_image_encryption_data() {
///     let encrypted_blob = download_from_blossom(&info.image_hash).await?;
///     let image = decrypt_group_image(&encrypted_blob, &info.image_key, &info.image_nonce)?;
/// }
/// ```
pub fn decrypt_group_image(
    encrypted_data: &[u8],
    image_key: &[u8; 32],
    image_nonce: &[u8; 12],
) -> Result<Vec<u8>, GroupImageError> {
    let cipher = ChaCha20Poly1305::new_from_slice(image_key).map_err(|e| {
        GroupImageError::DecryptionFailed {
            reason: format!("Failed to create cipher: {}", e),
        }
    })?;

    let nonce = Nonce::from_slice(image_nonce);
    let decrypted_data = cipher.decrypt(nonce, encrypted_data).map_err(|e| {
        GroupImageError::DecryptionFailed {
            reason: format!("Decryption failed (possible tampering): {}", e),
        }
    })?;

    Ok(decrypted_data)
}

/// Derive Blossom upload keypair from image_key
///
/// Uses HKDF-Expand with the context "mip01-blossom-upload-v1" to deterministically
/// derive a Nostr keypair from the image encryption key. This enables cleanup of old
/// images - anyone with the image_key can derive the upload keypair and delete the blob.
///
/// # Arguments
/// * `image_key` - The 32-byte image encryption key
///
/// # Returns
/// * Nostr keypair for Blossom authentication
///
/// # Example
/// ```ignore
/// // Cleanup old image after updating
/// if let Some(old_info) = old_extension.group_image_encryption_data() {
///     let old_keypair = derive_upload_keypair(&old_info.image_key)?;
///     blossom_client.delete(&old_info.image_hash, &old_keypair).await?;
/// }
/// ```
pub fn derive_upload_keypair(image_key: &[u8; 32]) -> Result<nostr::Keys, GroupImageError> {
    // Use HKDF-Expand to derive upload secret from image_key
    let hk = Hkdf::<Sha256>::new(None, image_key);
    let mut upload_secret = [0u8; 32];

    hk.expand(UPLOAD_KEYPAIR_CONTEXT, &mut upload_secret)
        .map_err(|e| GroupImageError::KeypairDerivationFailed {
            reason: format!("HKDF expansion failed: {}", e),
        })?;

    // Create Nostr keypair from derived secret
    let secret_key = nostr::SecretKey::from_slice(&upload_secret).map_err(|e| {
        GroupImageError::KeypairDerivationFailed {
            reason: format!("Invalid secret key: {}", e),
        }
    })?;

    Ok(nostr::Keys::new(secret_key))
}

/// Prepare group image for upload (encrypt + derive keypair)
///
/// This is a convenience function that encrypts the image and derives the upload keypair
/// in one step, returning everything needed for the upload workflow.
///
/// # Arguments
/// * `image_data` - Raw image bytes
///
/// # Returns
/// * `GroupImageUploadPrepared` with encrypted data, hash, and upload keypair
///
/// # Example
/// ```ignore
/// let prepared = prepare_group_image_for_upload(&image_bytes)?;
///
/// // Upload to Blossom
/// let blob_hash = blossom_client.upload(
///     &prepared.encrypted_data,
///     &prepared.upload_keypair
/// ).await?;
///
/// // Verify the Blossom response matches our hash
/// assert_eq!(blob_hash, prepared.encrypted_hash);
///
/// // Update extension with the verified hash
/// let update = NostrGroupDataUpdate::new()
///     .image_hash(Some(blob_hash))
///     .image_key(Some(prepared.image_key))
///     .image_nonce(Some(prepared.image_nonce));
/// ```
pub fn prepare_group_image_for_upload(
    image_data: &[u8],
) -> Result<GroupImageUploadPrepared, GroupImageError> {
    let encrypted = encrypt_group_image(image_data)?;
    let upload_keypair = derive_upload_keypair(&encrypted.image_key)?;

    Ok(GroupImageUploadPrepared {
        encrypted_data: encrypted.encrypted_data,
        encrypted_hash: encrypted.encrypted_hash,
        image_key: encrypted.image_key,
        image_nonce: encrypted.image_nonce,
        upload_keypair,
        original_size: image_data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original_data = b"This is a test group avatar image";

        // Encrypt
        let encrypted = encrypt_group_image(original_data).unwrap();
        assert_ne!(encrypted.encrypted_data.as_slice(), original_data);
        assert!(encrypted.encrypted_data.len() > original_data.len()); // Includes auth tag

        // Decrypt
        let decrypted = decrypt_group_image(
            &encrypted.encrypted_data,
            &encrypted.image_key,
            &encrypted.image_nonce,
        )
        .unwrap();

        assert_eq!(decrypted.as_slice(), original_data);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let original_data = b"Test image data";
        let encrypted = encrypt_group_image(original_data).unwrap();

        let wrong_key = [0x42u8; 32];
        let result = decrypt_group_image(
            &encrypted.encrypted_data,
            &wrong_key,
            &encrypted.image_nonce,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_decrypt_with_wrong_nonce() {
        let original_data = b"Test image data";
        let encrypted = encrypt_group_image(original_data).unwrap();

        let wrong_nonce = [0x24u8; 12];
        let result = decrypt_group_image(
            &encrypted.encrypted_data,
            &encrypted.image_key,
            &wrong_nonce,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_derive_upload_keypair_deterministic() {
        let image_key = [0x42u8; 32];

        let keypair1 = derive_upload_keypair(&image_key).unwrap();
        let keypair2 = derive_upload_keypair(&image_key).unwrap();

        // Same key should derive same keypair
        assert_eq!(keypair1.public_key(), keypair2.public_key());
        // Both should have the same secret key bytes
        assert_eq!(
            keypair1.secret_key().as_secret_bytes(),
            keypair2.secret_key().as_secret_bytes()
        );
    }

    #[test]
    fn test_derive_upload_keypair_different_keys() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        let keypair1 = derive_upload_keypair(&key1).unwrap();
        let keypair2 = derive_upload_keypair(&key2).unwrap();

        // Different keys should derive different keypairs
        assert_ne!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_prepare_group_image_for_upload() {
        let image_data = b"Test group avatar";

        let prepared = prepare_group_image_for_upload(image_data).unwrap();

        // Verify all fields are populated
        assert!(!prepared.encrypted_data.is_empty());
        assert_eq!(prepared.original_size, image_data.len());

        // Verify the encrypted hash matches the actual hash
        let calculated_hash: [u8; 32] = Sha256::digest(&prepared.encrypted_data).into();
        assert_eq!(prepared.encrypted_hash, calculated_hash);

        // Verify we can decrypt
        let decrypted =
            decrypt_group_image(&prepared.encrypted_data, &prepared.image_key, &prepared.image_nonce)
                .unwrap();
        assert_eq!(decrypted.as_slice(), image_data);

        // Verify keypair derivation is correct
        let derived_keypair = derive_upload_keypair(&prepared.image_key).unwrap();
        assert_eq!(
            derived_keypair.public_key(),
            prepared.upload_keypair.public_key()
        );
    }

    #[test]
    fn test_encrypted_hash_calculation() {
        let image_data = b"Test data for hash";
        let encrypted = encrypt_group_image(image_data).unwrap();

        // Verify hash matches
        let calculated_hash: [u8; 32] = Sha256::digest(&encrypted.encrypted_data).into();
        assert_eq!(calculated_hash, encrypted.encrypted_hash);
    }

    #[test]
    fn test_tampering_detection() {
        let original_data = b"Original group image";
        let encrypted = encrypt_group_image(original_data).unwrap();

        // Tamper with encrypted data
        let mut tampered = encrypted.encrypted_data.clone();
        tampered[0] ^= 0xFF;

        // Decryption should fail
        let result = decrypt_group_image(&tampered, &encrypted.image_key, &encrypted.image_nonce);
        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::DecryptionFailed { .. })));
    }

}
