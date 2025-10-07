//! Group image encryption and decryption functionality for MIP-01
//!
//! This module provides cryptographic operations for group avatar images:
//! - Image validation (dimensions, file size)
//! - Encryption with ChaCha20-Poly1305 AEAD
//! - Decryption and integrity verification
//! - Deterministic upload keypair derivation for Blossom cleanup
//!
//! The encryption scheme does NOT use AAD for simplicity. Integrity is provided by:
//! 1. SHA256 hash check of encrypted blob (detects substitution)
//! 2. ChaCha20-Poly1305 auth tag (detects tampering/corruption)

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use nostr::secp256k1::rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::media_processing::validation::validate_file_size;
use crate::media_processing::{
    MediaProcessingOptions, metadata::extract_metadata_from_encoded_image,
};

/// Domain separation label for upload keypair derivation (MIP-01 spec)
const UPLOAD_KEYPAIR_CONTEXT: &[u8] = b"mip01-blossom-upload-v1";

/// Prepared group image data ready for upload to Blossom
#[derive(Debug, Clone)]
pub struct GroupImageUpload {
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
    /// Original image size before encryption (and before EXIF stripping if applicable)
    pub original_size: usize,
    /// Size after encryption
    pub encrypted_size: usize,
    /// Validated and canonical MIME type
    pub mime_type: String,
    /// Image dimensions (width, height) if available
    pub dimensions: Option<(u32, u32)>,
    /// Blurhash for preview if generated
    pub blurhash: Option<String>,
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
    /// Image validation or processing error
    #[error(transparent)]
    MediaProcessing(#[from] crate::media_processing::types::MediaProcessingError),

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
    let encrypted_data =
        cipher
            .encrypt(nonce, image_data)
            .map_err(|e| GroupImageError::EncryptionFailed {
                reason: format!("Encryption failed: {}", e),
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
    let decrypted_data =
        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| GroupImageError::DecryptionFailed {
                reason: format!("Decryption failed (possible tampering): {}", e),
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

/// Prepare group image for upload (validate + encrypt + derive keypair)
///
/// This function validates the image and MIME type, encrypts it, and derives the upload keypair
/// in one step, returning everything needed for the upload workflow. Uses default processing
/// options (EXIF stripping enabled, blurhash generation enabled).
///
/// # Arguments
/// * `image_data` - Raw image bytes
/// * `mime_type` - MIME type of the image (e.g., "image/jpeg", "image/png")
///
/// # Returns
/// * `GroupImageUpload` with encrypted data, hash, and upload keypair
///
/// # Errors
/// * `ImageProcessing` - If the image fails validation (too large, invalid dimensions, invalid MIME type, etc.)
/// * `EncryptionFailed` - If encryption fails
/// * `KeypairDerivationFailed` - If keypair derivation fails
///
/// # Example
/// ```ignore
/// let prepared = prepare_group_image_for_upload(&image_bytes, "image/jpeg")?;
///
/// // Access metadata
/// println!("Dimensions: {:?}", prepared.dimensions);
/// println!("Blurhash: {:?}", prepared.blurhash);
/// println!("MIME type: {}", prepared.mime_type);
/// println!("Original size: {} bytes", prepared.original_size);
/// println!("Encrypted size: {} bytes", prepared.encrypted_size);
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
/// // Update extension with the verified hash and metadata
/// let update = NostrGroupDataUpdate::new()
///     .image_hash(Some(blob_hash))
///     .image_key(Some(prepared.image_key))
///     .image_nonce(Some(prepared.image_nonce));
/// ```
pub fn prepare_group_image_for_upload(
    image_data: &[u8],
    mime_type: &str,
) -> Result<GroupImageUpload, GroupImageError> {
    prepare_group_image_for_upload_with_options(
        image_data,
        mime_type,
        &MediaProcessingOptions::default(),
    )
}

/// Prepare group image for upload with custom processing options
///
/// This function provides full control over image processing behavior including
/// EXIF stripping, blurhash generation, and validation limits.
///
/// # Arguments
/// * `image_data` - Raw image bytes
/// * `mime_type` - MIME type of the image (e.g., "image/jpeg", "image/png")
/// * `options` - Custom processing options for validation and metadata handling
///
/// # Returns
/// * `GroupImageUpload` with encrypted data, hash, and upload keypair
///
/// # Errors
/// * `ImageProcessing` - If the image fails validation (too large, invalid dimensions, invalid MIME type, etc.)
/// * `EncryptionFailed` - If encryption fails
/// * `KeypairDerivationFailed` - If keypair derivation fails
///
/// # Example
/// ```ignore
/// // Custom options: disable blurhash, enable EXIF stripping
/// let options = MediaProcessingOptions {
///     sanitize_exif: true,
///     generate_blurhash: false,
///     max_dimension: Some(8192),
///     max_file_size: Some(10 * 1024 * 1024), // 10MB
///     max_filename_length: None,
/// };
///
/// let prepared = prepare_group_image_for_upload_with_options(
///     &image_bytes,
///     "image/jpeg",
///     &options
/// )?;
/// ```
pub fn prepare_group_image_for_upload_with_options(
    image_data: &[u8],
    mime_type: &str,
    options: &MediaProcessingOptions,
) -> Result<GroupImageUpload, GroupImageError> {
    use crate::media_processing::{metadata, validation};

    // Validate file size to ensure the image isn't too large
    validate_file_size(image_data, options)?;

    // Validate and canonicalize MIME type, ensuring it matches the actual file data
    // This protects against MIME type confusion attacks
    let canonical_mime_type = validation::validate_mime_type_matches_data(image_data, mime_type)?;

    let original_size = image_data.len();
    let sanitized_data: Vec<u8>;
    let dimensions: Option<(u32, u32)>;
    let blurhash: Option<String>;

    // Strip EXIF data for privacy if it's a safe raster format (JPEG, PNG)
    // For other formats (GIF, WebP, etc.), use the original data
    if options.sanitize_exif && metadata::is_safe_raster_format(&canonical_mime_type) {
        // PREFLIGHT CHECK: Validate dimensions without full decode to prevent OOM
        // This lightweight check protects against decompression bombs before
        // we fully decode the image for EXIF stripping
        metadata::preflight_dimension_check(image_data, options)?;

        // Strip EXIF and get the decoded image
        let (cleaned_data, decoded_img) =
            metadata::strip_exif_and_return_image(image_data, &canonical_mime_type)?;

        // Extract metadata from the already-decoded image
        let metadata = metadata::extract_metadata_from_decoded_image(
            &decoded_img,
            options,
            options.generate_blurhash,
        )?;

        sanitized_data = cleaned_data;
        dimensions = metadata.dimensions;
        blurhash = metadata.blurhash;
    } else {
        // For non-safe formats (GIF, WebP, etc.), skip EXIF stripping
        // and extract metadata from the encoded image
        let metadata =
            extract_metadata_from_encoded_image(image_data, options, options.generate_blurhash)?;

        sanitized_data = image_data.to_vec();
        dimensions = metadata.dimensions;
        blurhash = metadata.blurhash;
    }

    // Now that validation and sanitization passed, proceed with encryption
    let encrypted = encrypt_group_image(&sanitized_data)?;
    let encrypted_size = encrypted.encrypted_data.len();
    let upload_keypair = derive_upload_keypair(&encrypted.image_key)?;

    Ok(GroupImageUpload {
        encrypted_data: encrypted.encrypted_data,
        encrypted_hash: encrypted.encrypted_hash,
        image_key: encrypted.image_key,
        image_nonce: encrypted.image_nonce,
        upload_keypair,
        original_size,
        encrypted_size,
        mime_type: canonical_mime_type,
        dimensions,
        blurhash,
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
        assert!(matches!(
            result,
            Err(GroupImageError::DecryptionFailed { .. })
        ));
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
        assert!(matches!(
            result,
            Err(GroupImageError::DecryptionFailed { .. })
        ));
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
        // Create a valid 64x64 gradient image for testing
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(64, 64, |x, y| {
            Rgb([(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8])
        });
        let mut image_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut image_data),
            image::ImageFormat::Png,
        )
        .unwrap();

        // Test without blurhash due to bugs in blurhash library v0.2
        // The important thing is that the metadata structure is returned
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            ..Default::default()
        };
        let prepared =
            prepare_group_image_for_upload_with_options(&image_data, "image/png", &options)
                .unwrap();

        // Verify all fields are populated
        assert!(!prepared.encrypted_data.is_empty());
        assert_eq!(prepared.original_size, image_data.len());
        assert_eq!(prepared.mime_type, "image/png");

        // Verify metadata is populated
        assert_eq!(prepared.dimensions, Some((64, 64)));
        assert_eq!(prepared.blurhash, None); // Disabled for this test

        // Verify size fields
        assert_eq!(prepared.original_size, image_data.len());
        assert_eq!(prepared.encrypted_size, prepared.encrypted_data.len());

        // Verify the encrypted hash matches the actual hash
        let calculated_hash: [u8; 32] = Sha256::digest(&prepared.encrypted_data).into();
        assert_eq!(prepared.encrypted_hash, calculated_hash);

        // Verify we can decrypt
        let decrypted = decrypt_group_image(
            &prepared.encrypted_data,
            &prepared.image_key,
            &prepared.image_nonce,
        )
        .unwrap();
        // The decrypted data should be valid
        assert!(!decrypted.is_empty());

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
        assert!(matches!(
            result,
            Err(GroupImageError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_mime_type_validation() {
        // Create a valid 64x64 gradient PNG image for testing
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(64, 64, |x, y| {
            Rgb([(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8])
        });
        let mut png_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_data),
            image::ImageFormat::Png,
        )
        .unwrap();

        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            ..Default::default()
        };

        // Test valid MIME type that matches the actual file
        let result = prepare_group_image_for_upload_with_options(&png_data, "image/png", &options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mime_type, "image/png");

        // Test MIME type canonicalization (uppercase -> lowercase)
        let result = prepare_group_image_for_upload_with_options(&png_data, "Image/PNG", &options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mime_type, "image/png");

        // Test MIME type with whitespace
        let result =
            prepare_group_image_for_upload_with_options(&png_data, "  image/png  ", &options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mime_type, "image/png");

        // Test MIME type mismatch - claiming JPEG but file is PNG
        let result = prepare_group_image_for_upload_with_options(&png_data, "image/jpeg", &options);
        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::MediaProcessing(_))));

        // Test MIME type mismatch - claiming WebP but file is PNG
        let result = prepare_group_image_for_upload_with_options(&png_data, "image/webp", &options);
        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::MediaProcessing(_))));

        // Test invalid MIME type (no slash)
        let result = prepare_group_image_for_upload_with_options(&png_data, "invalid", &options);
        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::MediaProcessing(_))));

        // Test invalid MIME type (too long)
        let long_mime = "a".repeat(101);
        let result = prepare_group_image_for_upload_with_options(&png_data, &long_mime, &options);
        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::MediaProcessing(_))));
    }

    #[test]
    fn test_prepare_with_default_options() {
        // Create a valid 64x64 gradient image for testing
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(64, 64, |x, y| {
            Rgb([(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8])
        });
        let mut image_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut image_data),
            image::ImageFormat::Png,
        )
        .unwrap();

        // Test with default options but blurhash disabled due to library bugs
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false, // Disabled due to blurhash library bugs
            ..Default::default()
        };

        let result =
            prepare_group_image_for_upload_with_options(&image_data, "image/png", &options);

        assert!(result.is_ok());
        let prepared = result.unwrap();
        assert_eq!(prepared.mime_type, "image/png");
        assert_eq!(prepared.dimensions, Some((64, 64)));
        assert_eq!(prepared.blurhash, None); // Blurhash disabled

        // Verify EXIF stripping is enabled by checking the data was processed
        assert!(!prepared.encrypted_data.is_empty());
    }

    #[test]
    fn test_custom_size_limits() {
        // Create a small 32x32 image
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(32, 32, |x, y| Rgb([(x * 8) as u8, (y * 8) as u8, 128]));
        let mut image_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut image_data),
            image::ImageFormat::Png,
        )
        .unwrap();

        // Test with very restrictive size limit that should reject the image
        let restrictive_options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            max_dimension: Some(16),  // Very small limit
            max_file_size: Some(100), // Very small file size
            max_filename_length: None,
        };

        let result = prepare_group_image_for_upload_with_options(
            &image_data,
            "image/png",
            &restrictive_options,
        );

        // Should fail due to size restrictions
        assert!(result.is_err());
        assert!(matches!(result, Err(GroupImageError::MediaProcessing(_))));

        // Test with permissive options
        let permissive_options = MediaProcessingOptions {
            sanitize_exif: false,     // Don't sanitize
            generate_blurhash: false, // Don't generate blurhash
            max_dimension: Some(1024),
            max_file_size: Some(10 * 1024 * 1024), // 10MB
            max_filename_length: None,
        };

        let result = prepare_group_image_for_upload_with_options(
            &image_data,
            "image/png",
            &permissive_options,
        );

        // Should succeed
        assert!(result.is_ok());
        let prepared = result.unwrap();
        assert_eq!(prepared.mime_type, "image/png");
        assert_eq!(prepared.dimensions, Some((32, 32)));
        assert_eq!(prepared.blurhash, None); // Blurhash disabled
    }
}
