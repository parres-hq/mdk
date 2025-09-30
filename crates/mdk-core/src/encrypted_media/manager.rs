//! Main encrypted media manager
//!
//! This module contains the EncryptedMediaManager struct which provides the
//! high-level API for encrypting, decrypting, and managing encrypted media
//! within MLS groups on Nostr.

use nostr::{Tag as NostrTag, TagKind};
use sha2::{Digest, Sha256};

use crate::encrypted_media::crypto::{
    decrypt_data_with_aad, derive_encryption_key, derive_encryption_nonce, encrypt_data_with_aad,
};
use crate::encrypted_media::metadata::extract_and_process_metadata;
use crate::encrypted_media::types::{
    EncryptedMediaError, EncryptedMediaUpload, MediaProcessingOptions, MediaReference,
};
use crate::encrypted_media::validation::{validate_filename, validate_inputs, validate_mime_type};
use crate::{GroupId, MDK};
use mdk_storage_traits::MdkStorageProvider;

/// Manager for encrypted media operations
pub struct EncryptedMediaManager<'a, Storage>
where
    Storage: MdkStorageProvider,
{
    mdk: &'a MDK<Storage>,
    group_id: GroupId,
}

impl<'a, Storage> EncryptedMediaManager<'a, Storage>
where
    Storage: MdkStorageProvider,
{
    /// Create a new encrypted media manager for a specific group
    pub fn new(mdk: &'a MDK<Storage>, group_id: GroupId) -> Self {
        Self { mdk, group_id }
    }

    /// Encrypt media for upload with default options
    ///
    /// # Parameters
    /// - `data`: The raw media file data
    /// - `mime_type`: MIME type of the media (e.g., "image/jpeg")
    /// - `filename`: Original filename (required for AAD in encryption)
    pub fn encrypt_for_upload(
        &self,
        data: &[u8],
        mime_type: &str,
        filename: &str,
    ) -> Result<EncryptedMediaUpload, EncryptedMediaError> {
        self.encrypt_for_upload_with_options(
            data,
            mime_type,
            filename,
            &MediaProcessingOptions::default(),
        )
    }

    /// Encrypt media for upload with custom options
    ///
    /// # Parameters
    /// - `data`: The raw media file data
    /// - `mime_type`: MIME type of the media (e.g., "image/jpeg")
    /// - `filename`: Original filename (required for AAD in encryption)
    /// - `options`: Custom processing options for metadata handling
    pub fn encrypt_for_upload_with_options(
        &self,
        data: &[u8],
        mime_type: &str,
        filename: &str,
        options: &MediaProcessingOptions,
    ) -> Result<EncryptedMediaUpload, EncryptedMediaError> {
        let canonical_mime_type = validate_inputs(data, mime_type, filename, options)?;

        let metadata = extract_and_process_metadata(data, &canonical_mime_type, options)?;
        let original_hash: [u8; 32] = Sha256::digest(data).into();
        let encryption_key = derive_encryption_key(
            self.mdk,
            &self.group_id,
            &original_hash,
            &metadata.mime_type,
            filename,
        )?;
        let nonce = derive_encryption_nonce(
            self.mdk,
            &self.group_id,
            &original_hash,
            &metadata.mime_type,
            filename,
        )?;

        let encrypted_data = encrypt_data_with_aad(
            data,
            &encryption_key,
            &nonce,
            &original_hash,
            &metadata.mime_type,
            filename,
        )?;
        let encrypted_hash = Sha256::digest(&encrypted_data).into();
        let encrypted_size = encrypted_data.len() as u64;

        Ok(EncryptedMediaUpload {
            encrypted_data,
            original_hash,
            encrypted_hash,
            mime_type: metadata.mime_type,
            filename: filename.to_string(),
            original_size: data.len() as u64,
            encrypted_size,
            dimensions: metadata.dimensions,
            blurhash: metadata.blurhash,
        })
    }

    /// Decrypt downloaded media
    ///
    /// The filename for AAD is taken from the MediaReference, which was parsed from the imeta tag.
    pub fn decrypt_from_download(
        &self,
        encrypted_data: &[u8],
        reference: &MediaReference,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let encryption_key = derive_encryption_key(
            self.mdk,
            &self.group_id,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;
        let nonce = derive_encryption_nonce(
            self.mdk,
            &self.group_id,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;
        let decrypted_data = decrypt_data_with_aad(
            encrypted_data,
            &encryption_key,
            &nonce,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;

        let calculated_hash: [u8; 32] = Sha256::digest(&decrypted_data).into();
        if calculated_hash != reference.original_hash {
            return Err(EncryptedMediaError::HashVerificationFailed);
        }

        Ok(decrypted_data)
    }

    /// Create an imeta tag for encrypted media (after upload)
    ///
    /// Creates IMETA tag according to Marmot protocol 04.md specification:
    /// imeta url \<storage_url\> m \<mime_type\> filename \<original_filename\> [dim \<dimensions\>] [blurhash \<blurhash\>] x \<file_hash_hex\> v \<version\>
    pub fn create_imeta_tag(&self, upload: &EncryptedMediaUpload, uploaded_url: &str) -> NostrTag {
        let mut tag_values = vec![
            format!("url {}", uploaded_url),
            format!("m {}", upload.mime_type), // MIME type should already be canonical
            format!("filename {}", upload.filename),
        ];

        if let Some((width, height)) = upload.dimensions {
            tag_values.push(format!("dim {}x{}", width, height));
        }

        if let Some(ref blurhash) = upload.blurhash {
            tag_values.push(format!("blurhash {}", blurhash));
        }

        // x field contains SHA256 hash of original file content (hex-encoded)
        tag_values.push(format!("x {}", hex::encode(upload.original_hash)));

        // v field contains encryption version number (currently "mip04-v1")
        tag_values.push("v mip04-v1".to_string());

        NostrTag::custom(TagKind::Custom("imeta".into()), tag_values)
    }

    /// Create a media reference from upload result
    pub fn create_media_reference(
        &self,
        upload: &EncryptedMediaUpload,
        uploaded_url: String,
    ) -> MediaReference {
        MediaReference {
            url: uploaded_url,
            original_hash: upload.original_hash,
            mime_type: upload.mime_type.clone(),
            filename: upload.filename.clone(),
            dimensions: upload.dimensions,
        }
    }

    /// Parse an IMETA tag to create a MediaReference for decryption
    ///
    /// Expected IMETA format: url \<storage_url\> m \<mime_type\> filename \<filename\> x \<file_hash_hex\> v \<version\> [dim \<dimensions\>] [blurhash \<blurhash\>]
    pub fn parse_imeta_tag(
        &self,
        imeta_tag: &NostrTag,
    ) -> Result<MediaReference, EncryptedMediaError> {
        // Verify this is an imeta tag
        if imeta_tag.kind() != TagKind::Custom("imeta".into()) {
            return Err(EncryptedMediaError::InvalidImetaTag {
                reason: "Not an imeta tag".to_string(),
            });
        }

        let tag_values = imeta_tag.clone().to_vec();
        // Minimum required fields: url, m (MIME type), filename, x (hash), v (version) = 5 fields
        if tag_values.len() < 5 {
            return Err(EncryptedMediaError::InvalidImetaTag {
                reason: "IMETA tag has insufficient fields (minimum: url, m, filename, x, v)"
                    .to_string(),
            });
        }

        let mut url: Option<String> = None;
        let mut mime_type: Option<String> = None;
        let mut filename: Option<String> = None;
        let mut original_hash: Option<[u8; 32]> = None;
        let mut dimensions: Option<(u32, u32)> = None;
        let mut version: Option<String> = None;

        // Parse key-value pairs from IMETA tag
        // Skip the first element which is "imeta"
        for item in tag_values.iter().skip(1) {
            let parts: Vec<&str> = item.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }

            match parts[0] {
                "url" => url = Some(parts[1].to_string()),
                "m" => {
                    // Use centralized MIME type canonicalization to handle aliases properly
                    match validate_mime_type(parts[1]) {
                        Ok(canonical) => mime_type = Some(canonical),
                        Err(_) => {
                            return Err(EncryptedMediaError::InvalidImetaTag {
                                reason: format!("Invalid MIME type: {}", parts[1]),
                            });
                        }
                    }
                }
                "x" => {
                    // Decode hex-encoded original file hash
                    match hex::decode(parts[1]) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&bytes);
                            original_hash = Some(hash);
                        }
                        _ => {
                            return Err(EncryptedMediaError::InvalidImetaTag {
                                reason: "Invalid 'x' (file_hash) field".to_string(),
                            })
                        }
                    }
                }
                "dim" => {
                    // Parse dimensions in format "widthxheight"
                    let dim_parts: Vec<&str> = parts[1].split('x').collect();
                    if dim_parts.len() == 2 {
                        if let (Ok(width), Ok(height)) =
                            (dim_parts[0].parse::<u32>(), dim_parts[1].parse::<u32>())
                        {
                            dimensions = Some((width, height));
                        }
                    }
                }
                "filename" => match validate_filename(parts[1]) {
                    Ok(_) => filename = Some(parts[1].to_string()),
                    Err(_) => {
                        return Err(EncryptedMediaError::InvalidImetaTag {
                            reason: format!("Invalid filename: {}", parts[1]),
                        });
                    }
                },
                "v" => version = Some(parts[1].to_string()),
                "blurhash" => {
                    // Blurhash is optional and not needed for decryption
                }
                _ => {
                    // Ignore unknown fields for forward compatibility
                }
            }
        }

        // Validate required fields
        let url = url.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'url' field".to_string(),
        })?;
        let mime_type = mime_type.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'm' (mime_type) field".to_string(),
        })?;
        let original_hash = original_hash.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing or invalid 'x' (file_hash) field".to_string(),
        })?;
        let filename = filename.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'filename' field".to_string(),
        })?;

        // Validate version (required field, currently only support mip04-v1)
        let version = version.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'v' (version) field".to_string(),
        })?;
        if version != "mip04-v1" {
            return Err(EncryptedMediaError::DecryptionFailed {
                reason: format!("Unsupported MIP-04 encryption version: {}", version),
            });
        }

        Ok(MediaReference {
            url,
            original_hash,
            mime_type,
            filename,
            dimensions,
        })
    }
}

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Create an encrypted media manager for a specific group
    pub fn media_manager(&self, group_id: GroupId) -> EncryptedMediaManager<'_, Storage> {
        EncryptedMediaManager::new(self, group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdk_memory_storage::MdkMemoryStorage;

    fn create_test_mdk() -> MDK<MdkMemoryStorage> {
        MDK::new(MdkMemoryStorage::default())
    }

    #[test]
    fn test_create_imeta_tag() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            original_size: 1000,
            encrypted_size: 1004,
            dimensions: Some((1920, 1080)),
            blurhash: Some("LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string()),
        };

        let tag = manager.create_imeta_tag(&upload, "https://example.com/file.jpg");

        // Verify tag structure
        assert_eq!(tag.kind(), TagKind::Custom("imeta".into()));
        let values = tag.to_vec();

        // Check required fields
        assert!(values
            .iter()
            .any(|v| v.starts_with("url https://example.com/file.jpg")));
        assert!(values.iter().any(|v| v.starts_with("m image/jpeg")));
        assert!(values.iter().any(|v| v.starts_with("filename test.jpg")));
        assert!(values.iter().any(|v| v.starts_with("dim 1920x1080")));
        assert!(values
            .iter()
            .any(|v| v.starts_with("blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH")));
        assert!(values
            .iter()
            .any(|v| v.starts_with(&format!("x {}", hex::encode([0x42; 32])))));
        assert!(values.iter().any(|v| v.starts_with("v mip04-v1")));
    }

    #[test]
    fn test_parse_imeta_tag() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Create a valid IMETA tag
        let tag_values = vec![
            "url https://example.com/encrypted.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            "dim 1920x1080".to_string(),
            "blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v1".to_string(),
        ];

        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.url, "https://example.com/encrypted.jpg");
        assert_eq!(media_ref.mime_type, "image/jpeg");
        assert_eq!(media_ref.original_hash, [0x42; 32]);
        assert_eq!(media_ref.filename, "photo.jpg");
        assert_eq!(media_ref.dimensions, Some((1920, 1080)));
    }

    #[test]
    fn test_parse_imeta_tag_invalid() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test with wrong tag kind
        let wrong_tag = NostrTag::custom(TagKind::Custom("wrong".into()), vec!["test".to_string()]);
        let result = manager.parse_imeta_tag(&wrong_tag);
        assert!(result.is_err());

        // Test with missing required fields
        let incomplete_tag = NostrTag::custom(
            TagKind::Custom("imeta".into()),
            vec![
                "url https://example.com/test.jpg".to_string(),
                // Missing mime type and hash
            ],
        );
        let result = manager.parse_imeta_tag(&incomplete_tag);
        assert!(result.is_err());

        // Test with invalid hash
        let invalid_hash_tag = NostrTag::custom(
            TagKind::Custom("imeta".into()),
            vec![
                "url https://example.com/test.jpg".to_string(),
                "m image/jpeg".to_string(),
                "filename test.jpg".to_string(),
                "x invalidhash".to_string(),
            ],
        );
        let result = manager.parse_imeta_tag(&invalid_hash_tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_media_reference() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/png".to_string(),
            filename: "test.png".to_string(),
            original_size: 2000,
            encrypted_size: 2004,
            dimensions: Some((800, 600)),
            blurhash: None,
        };

        let media_ref = manager
            .create_media_reference(&upload, "https://cdn.example.com/image.png".to_string());

        assert_eq!(media_ref.url, "https://cdn.example.com/image.png");
        assert_eq!(media_ref.original_hash, [0x42; 32]);
        assert_eq!(media_ref.mime_type, "image/png");
        assert_eq!(media_ref.filename, "test.png");
        assert_eq!(media_ref.dimensions, Some((800, 600)));
    }

    #[test]
    fn test_encrypt_for_upload_accepts_any_mime_type() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test data (not real files, but that's fine for this test)
        let test_data = vec![0u8; 1000];
        // Use options that skip metadata extraction for images to avoid format errors
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            preserve_dimensions: false,
            generate_blurhash: false,
            max_dimension: None,
            max_file_size: None,
        };

        // Test with various non-image MIME types - all should pass validation
        let test_cases = vec![
            ("application/pdf", "document.pdf"),
            ("video/quicktime", "video.mov"),
            ("audio/mpeg", "song.mp3"),
            ("text/plain", "note.txt"),
            ("application/octet-stream", "file.bin"),
        ];

        for (mime_type, filename) in test_cases {
            let result =
                manager.encrypt_for_upload_with_options(&test_data, mime_type, filename, &options);

            // This will fail because we don't have a real MLS group, but we can check
            // that the validation passes and the error is about the missing group
            assert!(result.is_err());
            if let Err(EncryptedMediaError::GroupNotFound) = result {
                // This is expected - the MIME type validation passed, but we don't have a real group
            } else {
                panic!(
                    "Expected GroupNotFound error for MIME type {}, got: {:?}",
                    mime_type, result
                );
            }
        }
    }

    #[test]
    fn test_parse_imeta_tag_missing_fields() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test missing URL
        let tag_values = vec![
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing MIME type
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing filename
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing hash
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing version
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));
    }

    #[test]
    fn test_parse_imeta_tag_version_validation() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test unsupported version
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v2".to_string(), // Unsupported version
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DecryptionFailed { .. })
        ));

        // Test supported version
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v1".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_imeta_tag_optional_fields() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test with minimal required fields only
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v1".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.dimensions, None); // Optional field should be None

        // Test with dimensions
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v1".to_string(),
            "dim 1920x1080".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.dimensions, Some((1920, 1080)));
    }

    #[test]
    fn test_parse_imeta_tag_mime_type_canonicalization() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test with mixed-case MIME type
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m IMAGE/JPEG".to_string(), // Mixed case
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v1".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "image/jpeg"); // Should be lowercase

        // Test with whitespace around MIME type
        let tag_values = vec![
            "url https://example.com/test.png".to_string(),
            "m  Image/PNG  ".to_string(), // Whitespace and mixed case
            "filename photo.png".to_string(),
            format!("x {}", hex::encode([0x43; 32])),
            "v mip04-v1".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "image/png"); // Should be trimmed and lowercase

        // Test with various supported MIME types and case combinations
        let test_cases = vec![
            ("video/MP4", "video/mp4"),
            ("Audio/MPEG", "audio/mpeg"),
            ("IMAGE/webp", "image/webp"),
            ("AUDIO/wav", "audio/wav"),
        ];

        for (input_mime, expected_mime) in test_cases {
            let tag_values = vec![
                "url https://example.com/test.file".to_string(),
                format!("m {}", input_mime),
                "filename test.file".to_string(),
                format!("x {}", hex::encode([0x44; 32])),
                "v mip04-v1".to_string(),
            ];
            let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
            let result = manager.parse_imeta_tag(&tag);
            assert!(result.is_ok(), "Failed to parse MIME type: {}", input_mime);

            let media_ref = result.unwrap();
            assert_eq!(
                media_ref.mime_type, expected_mime,
                "MIME type canonicalization failed for input: {}",
                input_mime
            );
        }
    }

    #[test]
    fn test_imeta_roundtrip_with_mixed_case_mime() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Simulate an IMETA tag created by a producer that uses mixed-case MIME type
        let tag_values = vec![
            "url https://example.com/encrypted.jpg".to_string(),
            "m IMAGE/JPEG".to_string(), // Mixed case from producer
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v1".to_string(),
        ];
        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        // Parse the IMETA tag (this should canonicalize the MIME type)
        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();

        // Verify the MIME type was canonicalized to lowercase
        assert_eq!(media_ref.mime_type, "image/jpeg");
        assert_eq!(media_ref.url, "https://example.com/encrypted.jpg");
        assert_eq!(media_ref.filename, "photo.jpg");
        assert_eq!(media_ref.original_hash, [0x42; 32]);

        // The canonicalized MIME type should now work correctly for key derivation
        // and decryption operations (even though we can't test the full flow without
        // a real MLS group, we can verify the MediaReference structure is correct)
    }

    #[test]
    fn test_parse_imeta_tag_with_invalid_mime_type() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test parsing IMETA tag with any MIME type (all should be accepted)
        let tag_values = vec![
            "url https://example.com/test.pdf".to_string(),
            "m application/pdf".to_string(),
            "filename document.pdf".to_string(),
            format!("x {}", hex::encode([0x46; 32])),
            "v mip04-v1".to_string(),
        ];
        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_ok());
        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "application/pdf");

        // Test parsing IMETA tag with invalid MIME type format (no slash)
        let tag_values = vec![
            "url https://example.com/test.file".to_string(),
            "m invalid".to_string(), // Invalid format
            "filename test.file".to_string(),
            format!("x {}", hex::encode([0x47; 32])),
            "v mip04-v1".to_string(),
        ];
        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));
    }
}
