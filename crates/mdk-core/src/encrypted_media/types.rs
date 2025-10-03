//! Type definitions for encrypted media functionality
//!
//! This module contains all the core types, constants, and error definitions
//! used throughout the encrypted media system.

/// Maximum file size for encrypted media (100MB)
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum filename length
pub const MAX_FILENAME_LENGTH: usize = 210;

/// Maximum image dimension (width or height) - supports flagship phone cameras (200MP)
pub const MAX_IMAGE_DIMENSION: u32 = 16384;

/// Maximum total pixels allowed in an image (50 million pixels)
/// This prevents decompression bombs. At 50M pixels with 4 bytes per pixel (RGBA),
/// this allows ~200MB of decoded image data, which is reasonable for high-res images
/// but protects against malicious images that could exhaust memory.
pub const MAX_IMAGE_PIXELS: u64 = 50_000_000;

/// Maximum memory allowed for decoded images in MB (256MB)
/// This is a hard limit on memory allocation to prevent OOM from decompression bombs.
pub const MAX_IMAGE_MEMORY_MB: u64 = 256;

/// Configuration options for media processing
#[derive(Debug, Clone)]
pub struct MediaProcessingOptions {
    /// Sanitize EXIF and other metadata for privacy (default: true)
    pub sanitize_exif: bool,
    /// Preserve image dimensions in metadata (default: true)
    pub preserve_dimensions: bool,
    /// Generate blurhash for images (default: true)
    pub generate_blurhash: bool,
    /// Maximum allowed dimension for images (default: uses MAX_IMAGE_DIMENSION)
    pub max_dimension: Option<u32>,
    /// Custom size limit (default: uses MAX_FILE_SIZE)
    pub max_file_size: Option<usize>,
}

impl Default for MediaProcessingOptions {
    fn default() -> Self {
        Self {
            sanitize_exif: true,       // Privacy-first default
            preserve_dimensions: true, // Useful for display
            generate_blurhash: true,   // Good UX
            max_dimension: Some(MAX_IMAGE_DIMENSION),
            max_file_size: None,
        }
    }
}

/// Metadata extracted from media files
#[derive(Debug, Clone)]
pub struct MediaMetadata {
    /// MIME type of the media
    pub mime_type: String,
    /// Dimensions for images/videos (width, height)
    pub dimensions: Option<(u32, u32)>,
    /// Blurhash for images
    pub blurhash: Option<String>,
    /// Original file size in bytes
    pub original_size: u64,
}

/// Encrypted media ready for upload
#[derive(Debug, Clone)]
pub struct EncryptedMediaUpload {
    /// The encrypted media data
    pub encrypted_data: Vec<u8>,
    /// Hash of the original (unencrypted) data
    pub original_hash: [u8; 32],
    /// Hash of the encrypted data (for verification)
    pub encrypted_hash: [u8; 32],
    /// MIME type of the original media
    pub mime_type: String,
    /// Original filename
    pub filename: String,
    /// Size of original data before encryption
    pub original_size: u64,
    /// Size of encrypted data
    pub encrypted_size: u64,
    /// Image/video dimensions if applicable
    pub dimensions: Option<(u32, u32)>,
    /// Blurhash for images
    pub blurhash: Option<String>,
}

/// Reference to encrypted media
#[derive(Debug, Clone)]
pub struct MediaReference {
    /// URL where the encrypted media is stored
    pub url: String,
    /// Hash of original data for verification
    pub original_hash: [u8; 32],
    /// MIME type
    pub mime_type: String,
    /// Original filename
    pub filename: String,
    /// Dimensions if applicable
    pub dimensions: Option<(u32, u32)>,
}

/// Errors that can occur during encrypted media operations
#[derive(Debug, thiserror::Error)]
pub enum EncryptedMediaError {
    /// File is too large
    #[error("File size {size} exceeds maximum allowed size {max_size}")]
    FileTooLarge {
        /// The actual file size
        size: usize,
        /// The maximum allowed file size
        max_size: usize,
    },

    /// Unsupported MIME type
    #[error("MIME type '{mime_type}' is not supported")]
    UnsupportedMimeType {
        /// The unsupported MIME type
        mime_type: String,
    },

    /// Invalid MIME type format
    #[error("Invalid MIME type format: {mime_type}")]
    InvalidMimeType {
        /// The invalid MIME type
        mime_type: String,
    },

    /// Filename is too long
    #[error("Filename length {length} exceeds maximum {max_length}")]
    FilenameTooLong {
        /// The actual filename length
        length: usize,
        /// The maximum allowed filename length
        max_length: usize,
    },

    /// Filename is empty or invalid
    #[error("Filename cannot be empty")]
    EmptyFilename,

    /// Filename contains invalid characters
    #[error("Filename contains invalid characters")]
    InvalidFilename,

    /// Image dimensions are too large
    #[error("Image dimensions {width}x{height} exceed maximum {max_dimension}")]
    DimensionsTooLarge {
        /// The image width in pixels
        width: u32,
        /// The image height in pixels
        height: u32,
        /// The maximum allowed dimension
        max_dimension: u32,
    },

    /// Image has too many pixels (decompression bomb protection)
    #[error("Image has {total_pixels} pixels, exceeding maximum {max_pixels}")]
    TooManyPixels {
        /// Total number of pixels
        total_pixels: u64,
        /// Maximum allowed pixels
        max_pixels: u64,
    },

    /// Image would require too much memory to decode (decompression bomb protection)
    #[error("Image would require {estimated_mb}MB to decode, exceeding maximum {max_mb}MB")]
    ImageMemoryTooLarge {
        /// Estimated memory requirement in MB
        estimated_mb: u64,
        /// Maximum allowed memory in MB
        max_mb: u64,
    },

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

    /// Metadata extraction failed
    #[error("Failed to extract metadata: {reason}")]
    MetadataExtractionFailed {
        /// The reason for metadata extraction failure
        reason: String,
    },

    /// Hash verification failed
    #[error("Hash verification failed")]
    HashVerificationFailed,

    /// Group not found
    #[error("MLS group not found")]
    GroupNotFound,

    /// Invalid nonce
    #[error("Invalid encryption nonce")]
    InvalidNonce,

    /// Invalid IMETA tag format
    #[error("Invalid IMETA tag format: {reason}")]
    InvalidImetaTag {
        /// The reason for the invalid IMETA tag
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_processing_options_default() {
        let options = MediaProcessingOptions::default();
        assert!(options.sanitize_exif);
        assert!(options.preserve_dimensions);
        assert!(options.generate_blurhash);
        assert_eq!(options.max_dimension, Some(MAX_IMAGE_DIMENSION));
        assert_eq!(options.max_file_size, None);
    }

    #[test]
    fn test_media_processing_options() {
        let default_options = MediaProcessingOptions::default();
        assert!(default_options.sanitize_exif);
        assert!(default_options.preserve_dimensions);
        assert!(default_options.generate_blurhash);
        assert_eq!(default_options.max_dimension, Some(MAX_IMAGE_DIMENSION));
        assert_eq!(default_options.max_file_size, None);

        // Test custom options
        let custom_options = MediaProcessingOptions {
            sanitize_exif: false,
            preserve_dimensions: false,
            generate_blurhash: false,
            max_dimension: Some(1024),
            max_file_size: Some(1024 * 1024),
        };

        assert!(!custom_options.sanitize_exif);
        assert!(!custom_options.preserve_dimensions);
        assert!(!custom_options.generate_blurhash);
        assert_eq!(custom_options.max_dimension, Some(1024));
        assert_eq!(custom_options.max_file_size, Some(1024 * 1024));
    }

    #[test]
    fn test_encrypted_media_upload_structure() {
        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4, 5],
            original_hash: [0x01; 32],
            encrypted_hash: [0x02; 32],
            mime_type: "image/webp".to_string(),
            filename: "test.webp".to_string(),
            original_size: 5000,
            encrypted_size: 5016, // Original + ChaCha20-Poly1305 overhead
            dimensions: Some((1024, 768)),
            blurhash: Some("L6PZfSi_.AyE_3t7t7R**0o#DgR4".to_string()),
        };

        // Verify all fields are accessible
        assert_eq!(upload.encrypted_data.len(), 5);
        assert_eq!(upload.original_hash, [0x01; 32]);
        assert_eq!(upload.encrypted_hash, [0x02; 32]);
        assert_eq!(upload.mime_type, "image/webp");
        assert_eq!(upload.filename, "test.webp");
        assert_eq!(upload.original_size, 5000);
        assert_eq!(upload.encrypted_size, 5016);
        assert_eq!(upload.dimensions, Some((1024, 768)));
        assert!(upload.blurhash.is_some());
    }

    #[test]
    fn test_media_reference_structure() {
        let media_ref = MediaReference {
            url: "https://storage.example.com/abc123.enc".to_string(),
            original_hash: [0xFF; 32],
            mime_type: "video/mp4".to_string(),
            filename: "test.mp4".to_string(),
            dimensions: Some((1920, 1080)),
        };

        // Verify all fields are accessible
        assert_eq!(media_ref.url, "https://storage.example.com/abc123.enc");
        assert_eq!(media_ref.original_hash, [0xFF; 32]);
        assert_eq!(media_ref.mime_type, "video/mp4");
        assert_eq!(media_ref.filename, "test.mp4");
        assert_eq!(media_ref.dimensions, Some((1920, 1080)));
    }

    #[test]
    fn test_error_types() {
        // Test that all error types can be created and formatted properly
        let errors = vec![
            EncryptedMediaError::FileTooLarge {
                size: 1000,
                max_size: 500,
            },
            EncryptedMediaError::InvalidMimeType {
                mime_type: "invalid".to_string(),
            },
            EncryptedMediaError::FilenameTooLong {
                length: 300,
                max_length: 210,
            },
            EncryptedMediaError::EmptyFilename,
            EncryptedMediaError::DimensionsTooLarge {
                width: 20000,
                height: 15000,
                max_dimension: 16384,
            },
            EncryptedMediaError::TooManyPixels {
                total_pixels: 100_000_000,
                max_pixels: 50_000_000,
            },
            EncryptedMediaError::ImageMemoryTooLarge {
                estimated_mb: 1024,
                max_mb: 256,
            },
            EncryptedMediaError::EncryptionFailed {
                reason: "Test encryption failure".to_string(),
            },
            EncryptedMediaError::DecryptionFailed {
                reason: "Test decryption failure".to_string(),
            },
            EncryptedMediaError::MetadataExtractionFailed {
                reason: "Test metadata failure".to_string(),
            },
            EncryptedMediaError::HashVerificationFailed,
            EncryptedMediaError::GroupNotFound,
            EncryptedMediaError::InvalidNonce,
            EncryptedMediaError::InvalidImetaTag {
                reason: "Test invalid tag".to_string(),
            },
        ];

        // Verify all errors can be formatted (tests Display implementation)
        for error in errors {
            let error_string = format!("{}", error);
            assert!(!error_string.is_empty());
        }
    }
}
