//! Input validation for encrypted media operations
//!
//! This module provides validation functions for media files, MIME types,
//! filenames, and other input parameters to ensure they meet security
//! and protocol requirements.

use crate::encrypted_media::types::{
    EncryptedMediaError, MAX_FILE_SIZE, MAX_FILENAME_LENGTH, MAX_IMAGE_MEMORY_MB, MAX_IMAGE_PIXELS,
    MediaProcessingOptions,
};

/// Validate input parameters for media encryption
///
/// Returns the canonical MIME type that should be used for all subsequent operations
pub fn validate_inputs(
    data: &[u8],
    mime_type: &str,
    filename: &str,
    options: &MediaProcessingOptions,
) -> Result<String, EncryptedMediaError> {
    validate_file_size(data, options)?;
    let canonical_mime_type = validate_mime_type(mime_type)?;
    validate_filename(filename)?;
    Ok(canonical_mime_type)
}

/// Validate file size against limits
pub fn validate_file_size(
    data: &[u8],
    options: &MediaProcessingOptions,
) -> Result<(), EncryptedMediaError> {
    let max_size = options.max_file_size.unwrap_or(MAX_FILE_SIZE);
    if data.len() > max_size {
        return Err(EncryptedMediaError::FileTooLarge {
            size: data.len(),
            max_size,
        });
    }
    Ok(())
}

/// Validate MIME type format
///
/// Returns the canonical (trimmed and lowercase) MIME type for consistent use
/// in cryptographic operations and comparisons.
///
/// This is the centralized function for MIME type canonicalization used throughout
/// the encrypted media system. All MIME type processing should use this function
/// to ensure consistency in encryption keys, AAD construction, and imeta tags.
///
/// Note: This accepts any valid MIME type format - there is no whitelist of
/// supported types, allowing maximum flexibility for different media types.
pub fn validate_mime_type(mime_type: &str) -> Result<String, EncryptedMediaError> {
    // Normalize the MIME type: trim whitespace and convert to lowercase
    let normalized = mime_type.trim().to_ascii_lowercase();

    // Validate MIME type format using normalized version
    if !normalized.contains('/') || normalized.len() > 100 {
        return Err(EncryptedMediaError::InvalidMimeType {
            mime_type: mime_type.to_string(),
        });
    }

    Ok(normalized)
}

/// Validate filename length and content
pub fn validate_filename(filename: &str) -> Result<(), EncryptedMediaError> {
    // Validate filename is not empty
    if filename.is_empty() {
        return Err(EncryptedMediaError::EmptyFilename);
    }

    // Validate filename length
    if filename.len() > MAX_FILENAME_LENGTH {
        return Err(EncryptedMediaError::FilenameTooLong {
            length: filename.len(),
            max_length: MAX_FILENAME_LENGTH,
        });
    }

    // Disallow path separators and control characters
    if filename.contains('/') || filename.contains('\\') || filename.chars().any(|c| c.is_control())
    {
        return Err(EncryptedMediaError::InvalidFilename);
    }

    Ok(())
}

/// Validate image dimensions against limits
///
/// This function checks both dimension limits and memory requirements to prevent
/// decompression bombs. Even if individual dimensions are within limits, the total
/// pixel count and estimated memory usage must also be reasonable.
pub fn validate_image_dimensions(
    width: u32,
    height: u32,
    options: &MediaProcessingOptions,
) -> Result<(), EncryptedMediaError> {
    // Check individual dimension limits
    if let Some(max_dim) = options.max_dimension
        && (width > max_dim || height > max_dim)
    {
        return Err(EncryptedMediaError::DimensionsTooLarge {
            width,
            height,
            max_dimension: max_dim,
        });
    }

    // Check total pixel count and memory to prevent decompression bombs
    let total_pixels = width as u64 * height as u64;

    // Check pixel count limit first
    if total_pixels > MAX_IMAGE_PIXELS {
        return Err(EncryptedMediaError::TooManyPixels {
            total_pixels,
            max_pixels: MAX_IMAGE_PIXELS,
        });
    }

    // Calculate memory with ceiling division to avoid underestimating
    let bytes_per_pixel = 4u64; // RGBA
    let total_bytes = total_pixels * bytes_per_pixel;
    let estimated_mb = total_bytes.div_ceil(1024 * 1024);

    // Check memory limit
    if estimated_mb > MAX_IMAGE_MEMORY_MB {
        return Err(EncryptedMediaError::ImageMemoryTooLarge {
            estimated_mb,
            max_mb: MAX_IMAGE_MEMORY_MB,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_inputs() {
        let options = MediaProcessingOptions::default();

        // Test valid inputs with common image type
        let data = vec![0u8; 1000];
        let result = validate_inputs(&data, "image/jpeg", "test.jpg", &options);
        assert_eq!(result.unwrap(), "image/jpeg");

        // Test valid inputs with any MIME type (no longer restricted)
        let result = validate_inputs(&data, "application/pdf", "test.pdf", &options);
        assert_eq!(result.unwrap(), "application/pdf");

        // Test file too large
        let large_data = vec![0u8; MAX_FILE_SIZE + 1];
        let result = validate_inputs(&large_data, "image/jpeg", "test.jpg", &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FileTooLarge { .. })
        ));

        // Test invalid MIME type format
        let result = validate_inputs(&data, "invalid", "test.jpg", &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidMimeType { .. })
        ));

        // Test filename too long
        let long_filename = "a".repeat(MAX_FILENAME_LENGTH + 1);
        let result = validate_inputs(&data, "image/jpeg", &long_filename, &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FilenameTooLong { .. })
        ));

        // Test empty filename
        let result = validate_inputs(&data, "image/jpeg", "", &options);
        assert!(matches!(result, Err(EncryptedMediaError::EmptyFilename)));

        // Test valid inputs with various MIME types
        let result = validate_inputs(&data, "image/jpeg", "test.jpg", &options);
        assert!(result.is_ok());

        let result = validate_inputs(&data, "video/quicktime", "test.mov", &options);
        assert!(result.is_ok());

        let result = validate_inputs(&data, "application/octet-stream", "test.bin", &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_file_size() {
        let options = MediaProcessingOptions::default();

        // Test valid size
        let valid_data = vec![0u8; 1000];
        assert!(validate_file_size(&valid_data, &options).is_ok());

        // Test too large
        let large_data = vec![0u8; MAX_FILE_SIZE + 1];
        let result = validate_file_size(&large_data, &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FileTooLarge { .. })
        ));

        // Test custom size limit
        let custom_options = MediaProcessingOptions {
            max_file_size: Some(500),
            ..Default::default()
        };
        let result = validate_file_size(&valid_data, &custom_options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn test_validate_mime_type() {
        // Test valid MIME types return canonical (lowercase) form
        assert_eq!(validate_mime_type("image/jpeg").unwrap(), "image/jpeg");
        assert_eq!(validate_mime_type("video/mp4").unwrap(), "video/mp4");
        assert_eq!(validate_mime_type("audio/wav").unwrap(), "audio/wav");
        assert_eq!(validate_mime_type("audio/mpeg").unwrap(), "audio/mpeg");

        // Test canonicalization (uppercase -> lowercase)
        assert_eq!(validate_mime_type("Image/JPEG").unwrap(), "image/jpeg");
        assert_eq!(validate_mime_type("VIDEO/MP4").unwrap(), "video/mp4");
        assert_eq!(validate_mime_type("Audio/WAV").unwrap(), "audio/wav");
        assert_eq!(validate_mime_type("Audio/MPEG").unwrap(), "audio/mpeg");

        // Test trimming whitespace
        assert_eq!(validate_mime_type("  image/jpeg  ").unwrap(), "image/jpeg");
        assert_eq!(validate_mime_type("\timage/png\n").unwrap(), "image/png");

        // Test combined normalization
        assert_eq!(validate_mime_type("  Image/WEBP  ").unwrap(), "image/webp");

        // Test that any valid MIME type format is accepted (no whitelist)
        assert_eq!(
            validate_mime_type("application/pdf").unwrap(),
            "application/pdf"
        );
        assert_eq!(validate_mime_type("text/plain").unwrap(), "text/plain");
        assert_eq!(
            validate_mime_type("video/quicktime").unwrap(),
            "video/quicktime"
        );
        assert_eq!(
            validate_mime_type("application/octet-stream").unwrap(),
            "application/octet-stream"
        );

        // Test invalid format (no slash)
        let result = validate_mime_type("invalid");
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidMimeType { .. })
        ));

        // Test too long
        let long_mime = "a".repeat(101);
        let result = validate_mime_type(&long_mime);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidMimeType { .. })
        ));
    }

    #[test]
    fn test_validate_filename() {
        // Test valid filename
        assert!(validate_filename("test.jpg").is_ok());
        assert!(validate_filename("my-photo.png").is_ok());

        // Test empty filename
        let result = validate_filename("");
        assert!(matches!(result, Err(EncryptedMediaError::EmptyFilename)));

        // Test too long filename
        let long_filename = "a".repeat(MAX_FILENAME_LENGTH + 1);
        let result = validate_filename(&long_filename);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FilenameTooLong { .. })
        ));

        // Test maximum length filename (should be valid)
        let max_filename = "a".repeat(MAX_FILENAME_LENGTH);
        assert!(validate_filename(&max_filename).is_ok());
    }

    #[test]
    fn test_validate_image_dimensions() {
        let options = MediaProcessingOptions::default();

        // Test valid dimensions
        assert!(validate_image_dimensions(1920, 1080, &options).is_ok());
        assert!(validate_image_dimensions(800, 600, &options).is_ok());

        // Test dimensions too large
        let result = validate_image_dimensions(20000, 15000, &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DimensionsTooLarge { .. })
        ));

        // Test with no dimension limit but still check memory
        let no_limit_options = MediaProcessingOptions {
            max_dimension: None,
            ..Default::default()
        };
        // 50000 x 40000 = 2 billion pixels, should fail pixel count check
        let result = validate_image_dimensions(50000, 40000, &no_limit_options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::TooManyPixels { .. })
        ));

        // Test reasonable high-res image (12000 x 4000 = 48M pixels, just under 50M limit)
        assert!(validate_image_dimensions(12000, 4000, &no_limit_options).is_ok());

        // Test with custom dimension limit
        let custom_options = MediaProcessingOptions {
            max_dimension: Some(1024),
            ..Default::default()
        };
        let result = validate_image_dimensions(2048, 1536, &custom_options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DimensionsTooLarge { .. })
        ));
    }

    #[test]
    fn test_validate_image_dimensions_decompression_bomb_protection() {
        let options = MediaProcessingOptions {
            max_dimension: None, // No individual dimension limit
            ..Default::default()
        };

        // Test exactly at pixel limit (should pass)
        // sqrt(50M) ≈ 7071, so 7071 x 7071 ≈ 50M pixels
        assert!(validate_image_dimensions(7071, 7071, &options).is_ok());

        // Test just over pixel limit (should fail with TooManyPixels)
        let result = validate_image_dimensions(7100, 7100, &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::TooManyPixels { .. })
        ));
        if let Err(EncryptedMediaError::TooManyPixels {
            total_pixels,
            max_pixels,
        }) = result
        {
            assert_eq!(total_pixels, 7100 * 7100);
            assert_eq!(max_pixels, MAX_IMAGE_PIXELS);
        }

        // Test extreme decompression bomb attempt
        // 16384 x 16384 = 268M pixels, would be ~1GB RAM
        // This should fail the pixel count check first
        let result = validate_image_dimensions(16384, 16384, &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::TooManyPixels { .. })
        ));
        if let Err(EncryptedMediaError::TooManyPixels {
            total_pixels,
            max_pixels,
        }) = result
        {
            assert_eq!(total_pixels, 16384 * 16384);
            assert_eq!(max_pixels, MAX_IMAGE_PIXELS);
        }

        // Test wide panorama (within limits)
        // 10000 x 4000 = 40M pixels, ~160MB
        assert!(validate_image_dimensions(10000, 4000, &options).is_ok());

        // Test tall image (within limits)
        assert!(validate_image_dimensions(4000, 10000, &options).is_ok());
    }

    #[test]
    fn test_validate_inputs_comprehensive() {
        let options = MediaProcessingOptions::default();

        // Test valid inputs return canonical MIME type
        let valid_data = vec![0u8; 1000];
        let result = validate_inputs(&valid_data, "image/jpeg", "valid_file.jpg", &options);
        assert_eq!(result.unwrap(), "image/jpeg");

        // Test canonicalization in validate_inputs
        let result = validate_inputs(&valid_data, "  Image/JPEG  ", "valid_file.jpg", &options);
        assert_eq!(result.unwrap(), "image/jpeg");

        // Test file too large
        let large_data = vec![0u8; MAX_FILE_SIZE + 1];
        let result = validate_inputs(&large_data, "image/jpeg", "large_file.jpg", &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FileTooLarge { .. })
        ));

        // Test that any valid MIME type is accepted (no whitelist)
        let result = validate_inputs(&valid_data, "application/pdf", "document.pdf", &options);
        assert_eq!(result.unwrap(), "application/pdf");

        // Test invalid MIME type format
        let result = validate_inputs(&valid_data, "invalid", "file.txt", &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidMimeType { .. })
        ));

        // Test filename too long
        let long_filename = "a".repeat(MAX_FILENAME_LENGTH + 1);
        let result = validate_inputs(&valid_data, "image/jpeg", &long_filename, &options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FilenameTooLong { .. })
        ));

        // Test custom file size limit
        let custom_options = MediaProcessingOptions {
            max_file_size: Some(500),
            ..Default::default()
        };
        let result = validate_inputs(&valid_data, "image/jpeg", "small_file.jpg", &custom_options);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::FileTooLarge { .. })
        ));
    }
}
