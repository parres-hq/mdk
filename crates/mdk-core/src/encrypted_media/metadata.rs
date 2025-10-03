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
///
/// SECURITY NOTE: For images with sanitize_exif=true, this function sanitizes FIRST
/// before extracting metadata. This ensures that any malicious metadata or exploits
/// in the original image cannot affect the metadata extraction process.
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
            let (cleaned_data, decoded_img) = strip_exif_and_return_image(data, mime_type)?;
            metadata = extract_metadata_from_decoded_image(&decoded_img, metadata, options)?;
            processed_data = cleaned_data;
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
/// Returns: (cleaned_data, decoded_image)
fn strip_exif_and_return_image(
    data: &[u8],
    mime_type: &str,
) -> Result<(Vec<u8>, image::DynamicImage), EncryptedMediaError> {
    use image::{ImageEncoder, ImageReader};

    // Decode the image once
    let img_reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
            reason: format!("Failed to read image for EXIF stripping: {}", e),
        })?;

    let img = img_reader
        .decode()
        .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
            reason: format!("Failed to decode image for EXIF stripping: {}", e),
        })?;

    // Re-encode the image without metadata
    let mut output = Cursor::new(Vec::new());

    match mime_type {
        "image/jpeg" => {
            use image::codecs::jpeg::JpegEncoder;
            let mut encoder = JpegEncoder::new(&mut output);
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
        "image/webp" => {
            use image::codecs::webp::WebPEncoder;
            let encoder = WebPEncoder::new_lossless(&mut output);
            encoder
                .encode(
                    img.as_bytes(),
                    img.width(),
                    img.height(),
                    img.color().into(),
                )
                .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                    reason: format!("Failed to re-encode WebP: {}", e),
                })?;
        }
        "image/gif" => {
            use image::codecs::gif::GifEncoder;
            let mut encoder = GifEncoder::new(&mut output);
            encoder
                .encode(
                    img.as_bytes(),
                    img.width(),
                    img.height(),
                    img.color().into(),
                )
                .map_err(|e| EncryptedMediaError::MetadataExtractionFailed {
                    reason: format!("Failed to re-encode GIF: {}", e),
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
}
