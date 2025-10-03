//! Metadata extraction and processing for encrypted media
//!
//! This module handles extraction and processing of metadata from media files,
//! with a focus on privacy and security. It strips EXIF data from images
//! by default and includes blurhash generation for previews.

use std::io::Cursor;

use crate::encrypted_media::types::{EncryptedMediaError, MediaMetadata, MediaProcessingOptions};
use crate::encrypted_media::validation::validate_image_dimensions;

/// Extract and process metadata from media file, optionally sanitizing the file
///
/// The mime_type parameter should be the canonical (normalized) MIME type
/// to ensure consistency in cryptographic operations.
///
/// Returns a tuple of (processed_data, metadata) where processed_data is either:
/// - The original data if sanitize_exif is false
/// - The sanitized data with EXIF stripped if sanitize_exif is true and it's an image
/// - The original data if sanitization is not supported (e.g., animated GIF/WebP)
///
/// SECURITY NOTE: For images with sanitize_exif=true, this function sanitizes FIRST
/// before extracting metadata. This ensures that any malicious metadata or exploits
/// in the original image cannot affect the metadata extraction process.
///
/// NOTE: For animated formats (GIF/WebP), sanitization will be skipped to avoid
/// flattening animations. The original file will be used instead, with a warning logged.
pub fn extract_and_process_metadata(
    data: &[u8],
    mime_type: &str,
    options: &MediaProcessingOptions,
) -> Result<(Vec<u8>, MediaMetadata), EncryptedMediaError> {
    let mut metadata = MediaMetadata {
        mime_type: mime_type.to_string(),
        dimensions: None,
        blurhash: None,
        original_size: data.len() as u64,
    };

    let processed_data: Vec<u8>;

    // Process image metadata if it's an image
    if mime_type.starts_with("image/") {
        // SECURITY: Sanitize first if requested, then extract metadata from clean image
        // This prevents malicious metadata from being processed during extraction
        if options.sanitize_exif {
            // Try to strip EXIF, but fall back to original data if it's not supported
            // (e.g., for animated GIF/WebP which would be flattened)
            match strip_exif_and_return_image(data, mime_type) {
                Ok((cleaned_data, decoded_img)) => {
                    metadata =
                        extract_metadata_from_decoded_image(&decoded_img, metadata, options)?;
                    processed_data = cleaned_data;
                }
                Err(_) => {
                    // Fall back to using original data without sanitization
                    // This happens for formats like animated GIF/WebP where sanitization
                    // would flatten the animation. We preserve the original file instead.
                    tracing::warn!(
                        "Could not sanitize EXIF for {} - using original data to preserve format",
                        mime_type
                    );
                    metadata = extract_metadata_from_encoded_image(data, metadata, options)?;
                    processed_data = data.to_vec();
                }
            }
        } else {
            // If not sanitizing, process original data
            metadata = extract_metadata_from_encoded_image(data, metadata, options)?;
            processed_data = data.to_vec();
        }
    } else {
        // For non-images, just use the original data
        // TODO: add support for sanitizing other media types
        processed_data = data.to_vec();
    }

    Ok((processed_data, metadata))
}

/// Extract metadata from an encoded image (decodes the image data first)
///
/// This function is used when NOT sanitizing - it decodes the original image data
/// and extracts dimensions and blurhash from it.
pub fn extract_metadata_from_encoded_image(
    data: &[u8],
    mut metadata: MediaMetadata,
    options: &MediaProcessingOptions,
) -> Result<MediaMetadata, EncryptedMediaError> {
    use image::ImageReader;

    // First, get dimensions without full decode for performance
    let img_reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
            reason: format!("Failed to read image: {}", e),
        })?;

    let (width, height) = img_reader.into_dimensions().map_err(|e| {
        EncryptedMediaError::MetadataExtractionFailed {
            reason: format!("Failed to get image dimensions: {}", e),
        }
    })?;

    // Validate dimensions early - fail fast if image is too large
    validate_image_dimensions(width, height, options)?;

    // Store dimensions if requested
    if options.preserve_dimensions {
        metadata.dimensions = Some((width, height));
    }

    // Only decode the full image if we need to generate blurhash
    if options.generate_blurhash {
        let img_reader = ImageReader::new(Cursor::new(data))
            .with_guessed_format()
            .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                reason: format!("Failed to read image for blurhash: {}", e),
            })?;

        let img =
            img_reader
                .decode()
                .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                    reason: format!("Failed to decode image for blurhash: {}", e),
                })?;

        metadata.blurhash = generate_blurhash(&img);
    }

    Ok(metadata)
}

/// Generate blurhash for an image
pub fn generate_blurhash(img: &image::DynamicImage) -> Option<String> {
    use blurhash::encode;

    // Resize image for blurhash (max 32x32 for performance)
    let small_img = img.resize(32, 32, image::imageops::FilterType::Lanczos3);
    let rgb_img = small_img.to_rgb8();

    encode(4, 3, rgb_img.width(), rgb_img.height(), rgb_img.as_raw()).ok()
}

/// Extract metadata from an already-decoded image
///
/// This function extracts dimensions and blurhash from a decoded DynamicImage,
/// avoiding the need to decode the image again.
fn extract_metadata_from_decoded_image(
    img: &image::DynamicImage,
    mut metadata: MediaMetadata,
    options: &MediaProcessingOptions,
) -> Result<MediaMetadata, EncryptedMediaError> {
    let width = img.width();
    let height = img.height();

    // Validate dimensions
    validate_image_dimensions(width, height, options)?;

    // Store dimensions if requested
    if options.preserve_dimensions {
        metadata.dimensions = Some((width, height));
    }

    // Generate blurhash if requested
    if options.generate_blurhash {
        metadata.blurhash = generate_blurhash(img);
    }

    Ok(metadata)
}

/// Strip ALL EXIF data from an image and return both the encoded data and decoded image
///
/// This function re-encodes the image to remove all EXIF metadata for privacy.
/// It returns both the cleaned encoded bytes and the decoded image object to avoid
/// needing to decode again for metadata extraction.
///
/// IMPORTANT: For animated formats (GIF/WebP), this currently cannot preserve animations
/// and will return an error. Future work should handle these formats properly.
///
/// Returns: (cleaned_data, decoded_image)
fn strip_exif_and_return_image(
    data: &[u8],
    mime_type: &str,
) -> Result<(Vec<u8>, image::DynamicImage), EncryptedMediaError> {
    use image::{ImageEncoder, ImageReader};

    // TODO: Properly handle sanitizing animated GIF and WebP images in the future
    // Currently, decoding these formats only returns the first frame, which flattens
    // animations. We should either:
    // 1. Detect if the image is animated and skip sanitization with a clear error
    // 2. Use specialized libraries (image-gif, libwebp) to preserve all frames
    // 3. Process each frame individually and re-encode the animation
    if mime_type == "image/gif" || mime_type == "image/webp" {
        return Err(EncryptedMediaError::MetadataExtractionFailed {
            reason: format!(
                "Animated format {} sanitization not yet supported - this would flatten animations. \
                 Use sanitize_exif=false to preserve the original file.",
                mime_type
            ),
        });
    }

    // Decode the image once
    let img_reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
            reason: format!("Failed to read image for EXIF stripping: {}", e),
        })?;

    let mut img =
        img_reader
            .decode()
            .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                reason: format!("Failed to decode image for EXIF stripping: {}", e),
            })?;

    // Apply EXIF orientation transform before re-encoding
    // This "bakes in" the correct orientation so the image displays correctly
    // even without EXIF metadata
    img = apply_exif_orientation(data, img)?;

    // Re-encode the image without metadata
    let mut output = Cursor::new(Vec::new());

    match mime_type {
        "image/jpeg" => {
            use image::codecs::jpeg::JpegEncoder;
            // Use high quality (95) to minimize quality loss during re-encoding
            // This is important for preserving image fidelity while still stripping metadata
            let mut encoder = JpegEncoder::new_with_quality(&mut output, 100);
            encoder
                .encode(
                    img.as_bytes(),
                    img.width(),
                    img.height(),
                    img.color().into(),
                )
                .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                    reason: format!("Failed to re-encode JPEG: {}", e),
                })?;
        }
        "image/png" => {
            use image::codecs::png::PngEncoder;
            let encoder = PngEncoder::new(&mut output);
            encoder
                .write_image(
                    img.as_bytes(),
                    img.width(),
                    img.height(),
                    img.color().into(),
                )
                .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                    reason: format!("Failed to re-encode PNG: {}", e),
                })?;
        }
        _ => {
            // For unknown formats, return error
            return Err(EncryptedMediaError::MetadataExtractionFailed {
                reason: format!("Unsupported image format for EXIF stripping: {}", mime_type),
            });
        }
    }

    Ok((output.into_inner(), img))
}

/// Apply EXIF orientation transform to an image
///
/// Reads the EXIF orientation tag from the original image data and applies
/// the appropriate rotation and/or flip operations to the decoded image.
/// This ensures images display correctly even after EXIF metadata is stripped.
///
/// EXIF Orientation values:
/// 1 = Normal
/// 2 = Flip horizontal
/// 3 = Rotate 180°
/// 4 = Flip vertical
/// 5 = Flip horizontal + Rotate 270° CW
/// 6 = Rotate 90° CW
/// 7 = Flip horizontal + Rotate 90° CW
/// 8 = Rotate 270° CW
fn apply_exif_orientation(
    data: &[u8],
    img: image::DynamicImage,
) -> Result<image::DynamicImage, EncryptedMediaError> {
    use exif::{In, Reader, Tag};

    // Try to read EXIF data - if it fails or doesn't exist, just return the original image
    let exif_reader = match Reader::new().read_from_container(&mut Cursor::new(data)) {
        Ok(exif) => exif,
        Err(_) => return Ok(img), // No EXIF data or couldn't read it - return as-is
    };

    // Get the orientation tag
    let orientation = match exif_reader.get_field(Tag::Orientation, In::PRIMARY) {
        Some(field) => match field.value.get_uint(0) {
            Some(val) => val,
            None => return Ok(img), // Couldn't parse orientation - return as-is
        },
        None => return Ok(img), // No orientation tag - return as-is
    };

    // Apply the appropriate transform based on orientation value
    let transformed = match orientation {
        1 => img,                     // Normal - no transformation needed
        2 => img.fliph(),             // Flip horizontal
        3 => img.rotate180(),         // Rotate 180°
        4 => img.flipv(),             // Flip vertical
        5 => img.rotate270().fliph(), // Flip horizontal + Rotate 270° CW
        6 => img.rotate90(),          // Rotate 90° CW
        7 => img.rotate90().fliph(),  // Flip horizontal + Rotate 90° CW
        8 => img.rotate270(),         // Rotate 270° CW (or 90° CCW)
        _ => img,                     // Unknown orientation value - return as-is
    };

    Ok(transformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_metadata_from_encoded_image_dimension_validation() {
        use crate::encrypted_media::types::MediaProcessingOptions;

        // Create a simple 1x1 PNG image for testing
        let png_data = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
            0x49, 0x48, 0x44, 0x52, // IHDR
            0x00, 0x00, 0x00, 0x01, // Width: 1
            0x00, 0x00, 0x00, 0x01, // Height: 1
            0x08, 0x02, 0x00, 0x00,
            0x00, // Bit depth, color type, compression, filter, interlace
            0x90, 0x77, 0x53, 0xDE, // CRC
            0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
            0x49, 0x44, 0x41, 0x54, // IDAT
            0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0x00, // Compressed data
            0x02, 0x00, 0x01, // CRC
            0x00, 0x00, 0x00, 0x00, // IEND chunk length
            0x49, 0x45, 0x4E, 0x44, // IEND
            0xAE, 0x42, 0x60, 0x82, // CRC
        ];

        let metadata = MediaMetadata {
            mime_type: "image/png".to_string(),
            dimensions: None,
            blurhash: None,
            original_size: png_data.len() as u64,
        };

        // Test with dimension preservation enabled, blurhash disabled
        let options = MediaProcessingOptions {
            preserve_dimensions: true,
            generate_blurhash: false,
            sanitize_exif: true,
            max_dimension: Some(100),
            max_file_size: None,
        };

        let result = extract_metadata_from_encoded_image(&png_data, metadata.clone(), &options);
        assert!(result.is_ok());
        let processed = result.unwrap();
        assert_eq!(processed.dimensions, Some((1, 1)));
        assert!(processed.blurhash.is_none()); // Should be None since generate_blurhash is false

        // Test with dimension validation failure
        let strict_options = MediaProcessingOptions {
            preserve_dimensions: true,
            generate_blurhash: false,
            sanitize_exif: true,
            max_dimension: Some(0), // This should cause validation to fail
            max_file_size: None,
        };

        let result = extract_metadata_from_encoded_image(&png_data, metadata, &strict_options);
        assert!(result.is_err());
        if let Err(EncryptedMediaError::DimensionsTooLarge {
            width,
            height,
            max_dimension,
        }) = result
        {
            assert_eq!(width, 1);
            assert_eq!(height, 1);
            assert_eq!(max_dimension, 0);
        } else {
            panic!("Expected DimensionsTooLarge error");
        }
    }

    #[test]
    fn test_animated_format_fallback() {
        use crate::encrypted_media::types::MediaProcessingOptions;

        // Create a minimal valid GIF (not actually animated, but format is GIF)
        let gif_data = vec![
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a header
            0x01, 0x00, 0x01, 0x00, // Width: 1, Height: 1
            0x80, 0x00, 0x00, // Global color table
            0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, // Black and white
            0x2C, 0x00, 0x00, 0x00, 0x00, // Image descriptor
            0x01, 0x00, 0x01, 0x00, 0x00, // Image dimensions
            0x02, 0x02, 0x44, 0x01, 0x00, // Image data
            0x3B, // Trailer
        ];

        let options = MediaProcessingOptions {
            preserve_dimensions: true,
            generate_blurhash: false,
            sanitize_exif: true, // Request sanitization
            max_dimension: Some(100),
            max_file_size: None,
        };

        // Test that GIF with sanitize_exif=true falls back to original data
        let result = extract_and_process_metadata(&gif_data, "image/gif", &options);
        assert!(
            result.is_ok(),
            "GIF processing should succeed with fallback"
        );

        let (processed_data, metadata) = result.unwrap();
        // Should return original data since sanitization isn't supported
        assert_eq!(processed_data, gif_data, "Should return original GIF data");
        assert_eq!(metadata.mime_type, "image/gif");
        assert_eq!(metadata.original_size, gif_data.len() as u64);

        // Test WebP fallback behavior
        let result = extract_and_process_metadata(&gif_data, "image/webp", &options);
        assert!(
            result.is_ok(),
            "WebP processing should succeed with fallback"
        );

        let (processed_data, _) = result.unwrap();
        // Should return original data since sanitization isn't supported
        assert_eq!(processed_data, gif_data, "Should return original WebP data");
    }

    #[test]
    fn test_animated_format_without_sanitize() {
        use crate::encrypted_media::types::MediaProcessingOptions;

        // Create a minimal valid GIF
        let gif_data = vec![
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a header
            0x01, 0x00, 0x01, 0x00, // Width: 1, Height: 1
            0x80, 0x00, 0x00, // Global color table
            0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, // Black and white
            0x2C, 0x00, 0x00, 0x00, 0x00, // Image descriptor
            0x01, 0x00, 0x01, 0x00, 0x00, // Image dimensions
            0x02, 0x02, 0x44, 0x01, 0x00, // Image data
            0x3B, // Trailer
        ];

        let options = MediaProcessingOptions {
            preserve_dimensions: true,
            generate_blurhash: false,
            sanitize_exif: false, // Don't sanitize
            max_dimension: Some(100),
            max_file_size: None,
        };

        // Test that GIF without sanitization works normally
        let result = extract_and_process_metadata(&gif_data, "image/gif", &options);
        assert!(
            result.is_ok(),
            "GIF processing without sanitization should succeed"
        );

        let (processed_data, metadata) = result.unwrap();
        assert_eq!(processed_data, gif_data, "Should return original GIF data");
        assert_eq!(metadata.mime_type, "image/gif");
    }
}
