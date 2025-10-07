//! Image validation functions
//!
//! This module provides validation functions for image files, MIME types,
//! filenames, and other input parameters to ensure they meet security
//! and protocol requirements.

use std::io::Cursor;

use image::ImageReader;

use crate::media_processing::types::{
    MAX_FILE_SIZE, MAX_IMAGE_MEMORY_MB, MAX_IMAGE_PIXELS, MediaProcessingError,
    MediaProcessingOptions,
};

#[cfg(feature = "mip04")]
use crate::media_processing::types::MAX_FILENAME_LENGTH;

/// Validate file size against limits
pub(crate) fn validate_file_size(
    data: &[u8],
    options: &MediaProcessingOptions,
) -> Result<(), MediaProcessingError> {
    let max_size = options.max_file_size.unwrap_or(MAX_FILE_SIZE);
    if data.len() > max_size {
        return Err(MediaProcessingError::FileTooLarge {
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
/// the image processing system. All MIME type processing should use this function
/// to ensure consistency in encryption keys, AAD construction, and metadata.
///
/// Note: This accepts any valid MIME type format - there is no whitelist of
/// supported types, allowing maximum flexibility for different media types.
pub(crate) fn validate_mime_type(mime_type: &str) -> Result<String, MediaProcessingError> {
    // Normalize the MIME type: trim whitespace and convert to lowercase
    let normalized = mime_type.trim().to_ascii_lowercase();

    // Validate MIME type format using normalized version
    if !normalized.contains('/') || normalized.len() > 100 {
        return Err(MediaProcessingError::InvalidMimeType {
            mime_type: mime_type.to_string(),
        });
    }

    Ok(normalized)
}

/// Detect the actual MIME type from image file data
///
/// This function uses the `image` crate to detect the actual format of the image
/// by inspecting the file header/magic bytes, rather than trusting the provided MIME type.
///
/// # Arguments
/// * `data` - The image file data
///
/// # Returns
/// * The detected MIME type in canonical form (lowercase)
///
/// # Errors
/// * `InvalidMimeType` - If the image format cannot be detected
fn detect_mime_type_from_data(data: &[u8]) -> Result<String, MediaProcessingError> {
    let img_reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| MediaProcessingError::InvalidMimeType {
            mime_type: format!("Could not detect image format: {}", e),
        })?;

    let format = img_reader
        .format()
        .ok_or_else(|| MediaProcessingError::InvalidMimeType {
            mime_type: "Could not determine image format".to_string(),
        })?;

    // Convert image::ImageFormat to MIME type
    let mime_type = match format {
        image::ImageFormat::Png => "image/png",
        image::ImageFormat::Jpeg => "image/jpeg",
        image::ImageFormat::Gif => "image/gif",
        image::ImageFormat::WebP => "image/webp",
        image::ImageFormat::Bmp => "image/bmp",
        image::ImageFormat::Ico => "image/x-icon",
        image::ImageFormat::Tiff => "image/tiff",
        image::ImageFormat::Tga => "image/x-tga",
        image::ImageFormat::Dds => "image/vnd-ms.dds",
        image::ImageFormat::Hdr => "image/vnd.radiance",
        image::ImageFormat::OpenExr => "image/x-exr",
        image::ImageFormat::Pnm => "image/x-portable-anymap",
        image::ImageFormat::Farbfeld => "image/x-farbfeld",
        image::ImageFormat::Avif => "image/avif",
        image::ImageFormat::Qoi => "image/qoi",
        _ => {
            return Err(MediaProcessingError::InvalidMimeType {
                mime_type: format!("Unsupported image format: {:?}", format),
            });
        }
    };

    Ok(mime_type.to_string())
}

/// Validate that the provided MIME type matches the actual file data
///
/// This function detects the actual image format from the file data and compares
/// it with the provided MIME type. This prevents MIME type confusion attacks where
/// an attacker provides a misleading MIME type.
///
/// # Arguments
/// * `data` - The image file data
/// * `claimed_mime_type` - The MIME type claimed by the application
///
/// # Returns
/// * The canonical MIME type (validated and normalized)
///
/// # Errors
/// * `InvalidMimeType` - If the MIME type format is invalid
/// * `MimeTypeMismatch` - If the claimed MIME type doesn't match the detected format
///
/// # Security
/// This function protects against MIME type confusion attacks by verifying that the
/// claimed MIME type matches the actual file content. Applications cannot lie about
/// the file type.
pub(crate) fn validate_mime_type_matches_data(
    data: &[u8],
    claimed_mime_type: &str,
) -> Result<String, MediaProcessingError> {
    // First, validate and canonicalize the claimed MIME type
    let canonical_claimed = validate_mime_type(claimed_mime_type)?;

    // Detect the actual MIME type from the file data
    let detected_mime_type = detect_mime_type_from_data(data)?;

    // Compare the claimed type with the detected type
    if canonical_claimed != detected_mime_type {
        return Err(MediaProcessingError::MimeTypeMismatch {
            claimed: canonical_claimed,
            detected: detected_mime_type,
        });
    }

    Ok(canonical_claimed)
}

/// Validate filename length and content
#[cfg(feature = "mip04")]
pub(crate) fn validate_filename(filename: &str) -> Result<(), MediaProcessingError> {
    // Validate filename is not empty
    if filename.is_empty() {
        return Err(MediaProcessingError::EmptyFilename);
    }

    // Validate filename length
    if filename.len() > MAX_FILENAME_LENGTH {
        return Err(MediaProcessingError::FilenameTooLong {
            length: filename.len(),
            max_length: MAX_FILENAME_LENGTH,
        });
    }

    // Disallow path separators and control characters
    if filename.contains('/') || filename.contains('\\') || filename.chars().any(|c| c.is_control())
    {
        return Err(MediaProcessingError::InvalidFilename);
    }

    Ok(())
}

/// Validate image dimensions against limits
///
/// This function checks both dimension limits and memory requirements to prevent
/// decompression bombs. Even if individual dimensions are within limits, the total
/// pixel count and estimated memory usage must also be reasonable.
pub(crate) fn validate_image_dimensions(
    width: u32,
    height: u32,
    options: &MediaProcessingOptions,
) -> Result<(), MediaProcessingError> {
    // Check individual dimension limits
    if let Some(max_dim) = options.max_dimension
        && (width > max_dim || height > max_dim)
    {
        return Err(MediaProcessingError::ImageDimensionsTooLarge {
            width,
            height,
            max_dimension: max_dim,
        });
    }

    // Check total pixel count and memory to prevent decompression bombs
    let total_pixels = width as u64 * height as u64;

    // Check pixel count limit first
    if total_pixels > MAX_IMAGE_PIXELS {
        return Err(MediaProcessingError::ImageTooManyPixels {
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
        return Err(MediaProcessingError::ImageMemoryTooLarge {
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
    fn test_validate_file_size() {
        let options = MediaProcessingOptions::validation_only();

        // Test valid size
        let valid_data = vec![0u8; 1000];
        assert!(validate_file_size(&valid_data, &options).is_ok());

        // Test too large
        let large_data = vec![0u8; MAX_FILE_SIZE + 1];
        let result = validate_file_size(&large_data, &options);
        assert!(matches!(
            result,
            Err(MediaProcessingError::FileTooLarge { .. })
        ));

        // Test custom size limit
        let custom_options = MediaProcessingOptions {
            sanitize_exif: false,
            generate_blurhash: false,
            max_file_size: Some(500),
            ..Default::default()
        };
        let result = validate_file_size(&valid_data, &custom_options);
        assert!(matches!(
            result,
            Err(MediaProcessingError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn test_validate_mime_type() {
        // Test valid MIME types return canonical (lowercase) form
        assert_eq!(validate_mime_type("image/jpeg").unwrap(), "image/jpeg");
        assert_eq!(validate_mime_type("video/mp4").unwrap(), "video/mp4");
        assert_eq!(validate_mime_type("audio/wav").unwrap(), "audio/wav");

        // Test canonicalization (uppercase -> lowercase)
        assert_eq!(validate_mime_type("Image/JPEG").unwrap(), "image/jpeg");
        assert_eq!(validate_mime_type("VIDEO/MP4").unwrap(), "video/mp4");

        // Test trimming whitespace
        assert_eq!(validate_mime_type("  image/jpeg  ").unwrap(), "image/jpeg");
        assert_eq!(validate_mime_type("\timage/png\n").unwrap(), "image/png");

        // Test combined normalization
        assert_eq!(validate_mime_type("  Image/WEBP  ").unwrap(), "image/webp");

        // Test invalid format (no slash)
        let result = validate_mime_type("invalid");
        assert!(matches!(
            result,
            Err(MediaProcessingError::InvalidMimeType { .. })
        ));

        // Test too long
        let long_mime = "a".repeat(101);
        let result = validate_mime_type(&long_mime);
        assert!(matches!(
            result,
            Err(MediaProcessingError::InvalidMimeType { .. })
        ));
    }

    #[test]
    #[cfg(feature = "mip04")]
    fn test_validate_filename() {
        // Test valid filename
        assert!(validate_filename("test.jpg").is_ok());
        assert!(validate_filename("my-photo.png").is_ok());

        // Test empty filename
        let result = validate_filename("");
        assert!(matches!(result, Err(MediaProcessingError::EmptyFilename)));

        // Test too long filename
        let long_filename = "a".repeat(MAX_FILENAME_LENGTH + 1);
        let result = validate_filename(&long_filename);
        assert!(matches!(
            result,
            Err(MediaProcessingError::FilenameTooLong { .. })
        ));

        // Test maximum length filename (should be valid)
        let max_filename = "a".repeat(MAX_FILENAME_LENGTH);
        assert!(validate_filename(&max_filename).is_ok());

        // Test invalid characters
        assert!(matches!(
            validate_filename("path/to/file.jpg"),
            Err(MediaProcessingError::InvalidFilename)
        ));
        assert!(matches!(
            validate_filename("path\\to\\file.jpg"),
            Err(MediaProcessingError::InvalidFilename)
        ));
    }

    #[test]
    fn test_validate_image_dimensions() {
        let options = MediaProcessingOptions::validation_only();

        // Test valid dimensions
        assert!(validate_image_dimensions(1920, 1080, &options).is_ok());
        assert!(validate_image_dimensions(800, 600, &options).is_ok());

        // Test dimensions too large
        let result = validate_image_dimensions(20000, 15000, &options);
        assert!(matches!(
            result,
            Err(MediaProcessingError::ImageDimensionsTooLarge { .. })
        ));

        // Test with no dimension limit but still check memory
        let no_limit_options = MediaProcessingOptions {
            sanitize_exif: false,
            generate_blurhash: false,
            max_dimension: None,
            ..Default::default()
        };
        // 50000 x 40000 = 2 billion pixels, should fail pixel count check
        let result = validate_image_dimensions(50000, 40000, &no_limit_options);
        assert!(matches!(
            result,
            Err(MediaProcessingError::ImageTooManyPixels { .. })
        ));

        // Test reasonable high-res image (12000 x 4000 = 48M pixels, just under 50M limit)
        assert!(validate_image_dimensions(12000, 4000, &no_limit_options).is_ok());

        // Test with custom dimension limit
        let custom_options = MediaProcessingOptions {
            sanitize_exif: false,
            generate_blurhash: false,
            max_dimension: Some(1024),
            ..Default::default()
        };
        let result = validate_image_dimensions(2048, 1536, &custom_options);
        assert!(matches!(
            result,
            Err(MediaProcessingError::ImageDimensionsTooLarge { .. })
        ));
    }

    #[test]
    fn test_validate_image_dimensions_decompression_bomb_protection() {
        let options = MediaProcessingOptions {
            sanitize_exif: false,
            generate_blurhash: false,
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
            Err(MediaProcessingError::ImageTooManyPixels { .. })
        ));

        // Test extreme decompression bomb attempt
        // 16384 x 16384 = 268M pixels, would be ~1GB RAM
        let result = validate_image_dimensions(16384, 16384, &options);
        assert!(matches!(
            result,
            Err(MediaProcessingError::ImageTooManyPixels { .. })
        ));

        // Test wide panorama (within limits)
        // 10000 x 4000 = 40M pixels, ~160MB
        assert!(validate_image_dimensions(10000, 4000, &options).is_ok());

        // Test tall image (within limits)
        assert!(validate_image_dimensions(4000, 10000, &options).is_ok());
    }

    #[test]
    fn test_validate_mime_type_matches_data() {
        // Create a simple PNG image
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(8, 8, |x, y| {
            Rgb([(x * 32) as u8, (y * 32) as u8, ((x + y) * 16) as u8])
        });
        let mut png_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_data),
            image::ImageFormat::Png,
        )
        .unwrap();

        // Test matching MIME type
        let result = validate_mime_type_matches_data(&png_data, "image/png");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "image/png");

        // Test matching MIME type with canonicalization
        let result = validate_mime_type_matches_data(&png_data, "Image/PNG");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "image/png");

        // Test matching MIME type with whitespace
        let result = validate_mime_type_matches_data(&png_data, "  image/png  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "image/png");

        // Test mismatched MIME type (claiming JPEG but file is PNG)
        let result = validate_mime_type_matches_data(&png_data, "image/jpeg");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MediaProcessingError::MimeTypeMismatch { .. })
        ));

        // Test mismatched MIME type (claiming WebP but file is PNG)
        let result = validate_mime_type_matches_data(&png_data, "image/webp");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MediaProcessingError::MimeTypeMismatch { .. })
        ));

        // Create a JPEG image
        let mut jpeg_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut jpeg_data),
            image::ImageFormat::Jpeg,
        )
        .unwrap();

        // Test matching JPEG
        let result = validate_mime_type_matches_data(&jpeg_data, "image/jpeg");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "image/jpeg");

        // Test mismatched (claiming PNG but file is JPEG)
        let result = validate_mime_type_matches_data(&jpeg_data, "image/png");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MediaProcessingError::MimeTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_detect_mime_type_from_data() {
        // Create test images in different formats
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(8, 8, |x, y| {
            Rgb([(x * 32) as u8, (y * 32) as u8, ((x + y) * 16) as u8])
        });

        // Test PNG detection
        let mut png_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_data),
            image::ImageFormat::Png,
        )
        .unwrap();
        let result = detect_mime_type_from_data(&png_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "image/png");

        // Test JPEG detection
        let mut jpeg_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut jpeg_data),
            image::ImageFormat::Jpeg,
        )
        .unwrap();
        let result = detect_mime_type_from_data(&jpeg_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "image/jpeg");

        // Test invalid data
        let invalid_data = vec![0u8; 100];
        let result = detect_mime_type_from_data(&invalid_data);
        assert!(result.is_err());
    }
}
