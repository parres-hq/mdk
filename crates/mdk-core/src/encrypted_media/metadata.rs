//! Metadata extraction and processing for encrypted media
//!
//! This module handles extraction and processing of metadata from media files,
//! with a focus on privacy and security. It includes EXIF processing, image
//! metadata extraction, and blurhash generation.

use std::collections::HashMap;
use std::io::Cursor;

use exif::{Reader as ExifReader, Tag as ExifTag, Value as ExifValue};

use crate::encrypted_media::types::{EncryptedMediaError, MediaMetadata, MediaProcessingOptions};
use crate::encrypted_media::validation::validate_image_dimensions;

/// Extract and process metadata from media file
///
/// The mime_type parameter should be the canonical (normalized) MIME type
/// to ensure consistency in cryptographic operations.
pub fn extract_and_process_metadata(
    data: &[u8],
    mime_type: &str,
    options: &MediaProcessingOptions,
) -> Result<MediaMetadata, EncryptedMediaError> {
    let mut metadata = MediaMetadata {
        mime_type: mime_type.to_string(),
        dimensions: None,
        blurhash: None,
        original_size: data.len() as u64,
        cleaned_exif: HashMap::new(),
    };

    // Process image metadata if it's an image
    if mime_type.starts_with("image/") {
        metadata = process_image_metadata(data, metadata, options)?;
    }

    Ok(metadata)
}

/// Process image-specific metadata
pub fn process_image_metadata(
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

    // Process EXIF data (doesn't require image decode)
    if !options.sanitize_exif {
        metadata.cleaned_exif = extract_safe_exif(data);
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

/// Extract safe EXIF data (removing sensitive information)
///
/// This method implements a privacy-first approach to EXIF data handling:
/// 1. Strips all potentially sensitive metadata (GPS, device info, timestamps, etc.)
/// 2. Only preserves technical metadata that's safe for sharing
/// 3. Validates data integrity to detect potential exploits
pub fn extract_safe_exif(data: &[u8]) -> HashMap<String, String> {
    let mut safe_exif = HashMap::new();

    // Try to parse EXIF data
    let exif_reader = match ExifReader::new().read_from_container(&mut Cursor::new(data)) {
        Ok(exif) => exif,
        Err(_) => {
            // No EXIF data or parsing failed - return empty map (safest approach)
            return safe_exif;
        }
    };

    // Define safe EXIF fields that don't compromise privacy
    let safe_fields = get_safe_exif_fields();

    // Extract only safe fields
    for field in exif_reader.fields() {
        // Check if this field is in our safe list
        if let Some(safe_name) = safe_fields.get(&field.tag) {
            // Additional validation for specific fields
            if is_exif_value_safe(field.tag, &field.value) {
                let value_str = format_exif_value(&field.value);
                if !value_str.is_empty() && value_str.len() <= 100 {
                    safe_exif.insert(safe_name.clone(), value_str);
                }
            }
        }
    }

    // Perform basic security validation
    if let Err(e) = validate_exif_security(&exif_reader) {
        tracing::warn!("EXIF security validation failed: {}", e);
        // Return empty map for security - don't process potentially malicious EXIF
        return HashMap::new();
    }

    safe_exif
}

/// Get whitelist of safe EXIF fields that don't compromise privacy
pub fn get_safe_exif_fields() -> HashMap<ExifTag, String> {
    let mut safe_fields = HashMap::new();

    // Technical camera settings (safe to preserve)
    safe_fields.insert(ExifTag::FNumber, "f_number".to_string());
    safe_fields.insert(ExifTag::ExposureTime, "exposure_time".to_string());
    safe_fields.insert(ExifTag::ISOSpeed, "iso".to_string());
    safe_fields.insert(ExifTag::FocalLength, "focal_length".to_string());
    safe_fields.insert(ExifTag::Flash, "flash".to_string());
    safe_fields.insert(ExifTag::WhiteBalance, "white_balance".to_string());
    safe_fields.insert(ExifTag::ExposureMode, "exposure_mode".to_string());
    safe_fields.insert(ExifTag::SceneCaptureType, "scene_type".to_string());

    // Image technical properties (safe)
    safe_fields.insert(ExifTag::ColorSpace, "color_space".to_string());
    safe_fields.insert(ExifTag::Orientation, "orientation".to_string());
    safe_fields.insert(ExifTag::ResolutionUnit, "resolution_unit".to_string());
    safe_fields.insert(ExifTag::XResolution, "x_resolution".to_string());
    safe_fields.insert(ExifTag::YResolution, "y_resolution".to_string());

    // Note: We explicitly exclude:
    // - GPS data (Tag::GPSLatitude, Tag::GPSLongitude, etc.)
    // - Device identifiers (Tag::Make, Tag::Model, Tag::Software, Tag::SerialNumber)
    // - Timestamps (Tag::DateTime, Tag::DateTimeOriginal, Tag::DateTimeDigitized)
    // - User comments (Tag::UserComment, Tag::ImageDescription)
    // - Thumbnail data
    // - Maker notes (proprietary data that could contain anything)

    safe_fields
}

/// Validate that an EXIF value is safe to preserve
pub fn is_exif_value_safe(_tag: ExifTag, value: &ExifValue) -> bool {
    match value {
        // Reject any values that could contain embedded data or exploits
        ExifValue::Undefined(data, _) => {
            // Undefined data could contain anything - be very conservative
            data.len() <= 32 && is_data_safe(data)
        }
        ExifValue::Ascii(strings) => {
            // ASCII strings should be reasonable length and not contain suspicious patterns
            strings.iter().all(|s| {
                s.len() <= 50
                    && s.iter()
                        .all(|&b| b.is_ascii() && !char::from(b).is_control())
                    && !contains_suspicious_patterns(&String::from_utf8_lossy(s))
            })
        }
        // Numeric values are generally safe
        ExifValue::Byte(_)
        | ExifValue::Short(_)
        | ExifValue::Long(_)
        | ExifValue::SByte(_)
        | ExifValue::SShort(_)
        | ExifValue::SLong(_)
        | ExifValue::Float(_)
        | ExifValue::Double(_) => true,

        // Rational values are safe
        ExifValue::Rational(_) | ExifValue::SRational(_) => true,

        // Be conservative with unknown types
        _ => false,
    }
}

/// Check if binary data appears safe (no suspicious patterns)
pub fn is_data_safe(data: &[u8]) -> bool {
    // Check for suspicious patterns that might indicate embedded exploits

    // Reject data with too many null bytes (could be padding for exploits)
    let null_count = data.iter().filter(|&&b| b == 0).count();
    if null_count > data.len() / 2 {
        return false;
    }

    // Reject data with executable signatures
    if data.len() >= 2 {
        match &data[0..2] {
            [0x4D, 0x5A] => return false, // PE executable
            [0x7F, 0x45] => return false, // ELF executable
            [0xCA, 0xFE] => return false, // Mach-O executable
            [0xFE, 0xED] => return false, // Mach-O executable
            _ => {}
        }
    }

    // Check for script-like patterns
    if data.len() >= 4
        && (data.starts_with(b"<scr")
            || data.starts_with(b"java")
            || data.starts_with(b"#!/")
            || data.starts_with(b"<?ph"))
    {
        return false;
    }

    true
}

/// Check for suspicious patterns in ASCII strings
pub fn contains_suspicious_patterns(s: &str) -> bool {
    let suspicious_patterns = [
        "javascript:",
        "data:",
        "vbscript:",
        "file://",
        "ftp://",
        "<script",
        "</script",
        "<?php",
        "#!/",
        "cmd.exe",
        "powershell",
        "eval(",
        "exec(",
        "system(",
        "shell_exec",
        "passthru",
    ];

    let lower_s = s.to_lowercase();
    suspicious_patterns
        .iter()
        .any(|pattern| lower_s.contains(pattern))
}

/// Format EXIF value as string for storage
pub fn format_exif_value(value: &ExifValue) -> String {
    match value {
        ExifValue::Ascii(strings) => strings
            .iter()
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect::<Vec<_>>()
            .join("; "),
        ExifValue::Byte(values) => values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::Short(values) => values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::Long(values) => values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::Rational(values) => values
            .iter()
            .map(|r| {
                if r.denom == 0 {
                    "undefined".to_string()
                } else {
                    format!("{}/{}", r.num, r.denom)
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::SByte(values) => values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::SShort(values) => values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::SLong(values) => values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::SRational(values) => values
            .iter()
            .map(|r| {
                if r.denom == 0 {
                    "undefined".to_string()
                } else {
                    format!("{}/{}", r.num, r.denom)
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::Float(values) => values
            .iter()
            .map(|v| format!("{:.3}", v))
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::Double(values) => values
            .iter()
            .map(|v| format!("{:.3}", v))
            .collect::<Vec<_>>()
            .join(", "),
        ExifValue::Undefined(data, _) => {
            // For undefined data, only show length to avoid exposing content
            format!("binary({} bytes)", data.len())
        }
        _ => "unknown".to_string(),
    }
}

/// Perform basic security validation on EXIF data
///
/// Returns an error if potentially malicious patterns are detected
pub fn validate_exif_security(exif: &exif::Exif) -> Result<(), EncryptedMediaError> {
    // Check for suspicious field counts (potential DoS via memory exhaustion)
    if exif.fields().len() > 1000 {
        return Err(EncryptedMediaError::MetadataExtractionFailed {
            reason: format!(
                "EXIF data contains suspiciously high number of fields: {} (max: 1000)",
                exif.fields().len()
            ),
        });
    }

    // Check for fields with suspicious data sizes
    for field in exif.fields() {
        let value_size = match &field.value {
            ExifValue::Undefined(data, _) => data.len(),
            ExifValue::Ascii(strings) => strings.iter().map(|s| s.len()).sum(),
            _ => 0,
        };

        if value_size > 10000 {
            return Err(EncryptedMediaError::MetadataExtractionFailed {
                reason: format!(
                    "EXIF field {} contains suspiciously large data: {} bytes (max: 10000)",
                    field.tag, value_size
                ),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use exif::Rational;

    #[test]
    fn test_safe_exif_fields() {
        let safe_fields = get_safe_exif_fields();

        // Should include technical camera settings
        assert!(safe_fields.contains_key(&ExifTag::FNumber));
        assert!(safe_fields.contains_key(&ExifTag::ExposureTime));
        assert!(safe_fields.contains_key(&ExifTag::ISOSpeed));

        // Should include safe image properties
        assert!(safe_fields.contains_key(&ExifTag::Orientation));
        assert!(safe_fields.contains_key(&ExifTag::ColorSpace));

        // Should NOT include sensitive fields (we can't test for their absence directly
        // since they're not in our safe list, but we can verify our list is reasonably sized)
        assert!(safe_fields.len() < 20); // Should be a curated, small list
    }

    #[test]
    fn test_is_data_safe() {
        // Safe data
        assert!(is_data_safe(&[1, 2, 3, 4, 5]));
        assert!(is_data_safe(&[]));

        // Unsafe data - too many nulls
        assert!(!is_data_safe(&[0, 0, 0, 0, 0, 1]));

        // Unsafe data - executable signatures
        assert!(!is_data_safe(&[0x4D, 0x5A, 0x90, 0x00])); // PE
        assert!(!is_data_safe(&[0x7F, 0x45, 0x4C, 0x46])); // ELF
        assert!(!is_data_safe(&[0xCA, 0xFE, 0xBA, 0xBE])); // Mach-O

        // Unsafe data - script patterns
        assert!(!is_data_safe(b"<script>alert(1)</script>"));
        assert!(!is_data_safe(b"#!/bin/bash"));
        assert!(!is_data_safe(b"<?php echo 'hi'; ?>"));
    }

    #[test]
    fn test_contains_suspicious_patterns() {
        // Safe strings
        assert!(!contains_suspicious_patterns("Canon EOS R5"));
        assert!(!contains_suspicious_patterns("f/2.8"));
        assert!(!contains_suspicious_patterns("1/125"));

        // Suspicious strings
        assert!(contains_suspicious_patterns("javascript:alert(1)"));
        assert!(contains_suspicious_patterns("data:text/html,<script>"));
        assert!(contains_suspicious_patterns("file:///etc/passwd"));
        assert!(contains_suspicious_patterns("eval(document.cookie)"));
        assert!(contains_suspicious_patterns("cmd.exe /c dir"));
        assert!(contains_suspicious_patterns(
            "<?php system($_GET['cmd']); ?>"
        ));
    }

    #[test]
    fn test_is_exif_value_safe() {
        // Safe values
        assert!(is_exif_value_safe(
            ExifTag::FNumber,
            &ExifValue::Rational(vec![Rational { num: 28, denom: 10 }])
        ));
        assert!(is_exif_value_safe(
            ExifTag::ISOSpeed,
            &ExifValue::Short(vec![800])
        ));
        assert!(is_exif_value_safe(
            ExifTag::Flash,
            &ExifValue::Short(vec![16])
        ));

        // Safe ASCII
        assert!(is_exif_value_safe(
            ExifTag::ColorSpace,
            &ExifValue::Ascii(vec![b"sRGB".to_vec()])
        ));

        // Unsafe ASCII - too long
        let long_string = "a".repeat(100);
        assert!(!is_exif_value_safe(
            ExifTag::ColorSpace,
            &ExifValue::Ascii(vec![long_string.into_bytes()])
        ));

        // Unsafe ASCII - suspicious content
        assert!(!is_exif_value_safe(
            ExifTag::ColorSpace,
            &ExifValue::Ascii(vec![b"javascript:alert(1)".to_vec()])
        ));

        // Unsafe undefined data - too large
        let large_data = vec![0u8; 100];
        assert!(!is_exif_value_safe(
            ExifTag::ColorSpace,
            &ExifValue::Undefined(large_data, 0)
        ));

        // Unsafe undefined data - suspicious content
        assert!(!is_exif_value_safe(
            ExifTag::ColorSpace,
            &ExifValue::Undefined(vec![0x4D, 0x5A, 0x90, 0x00], 0)
        ));
    }

    #[test]
    fn test_format_exif_value() {
        // Test different value types
        assert_eq!(
            format_exif_value(&ExifValue::Ascii(vec![b"sRGB".to_vec()])),
            "sRGB"
        );
        assert_eq!(format_exif_value(&ExifValue::Short(vec![800])), "800");
        assert_eq!(
            format_exif_value(&ExifValue::Rational(vec![Rational { num: 28, denom: 10 }])),
            "28/10"
        );
        assert_eq!(format_exif_value(&ExifValue::Float(vec![2.8])), "2.800");

        // Test multiple values
        assert_eq!(
            format_exif_value(&ExifValue::Short(vec![800, 1600])),
            "800, 1600"
        );

        // Test undefined data (should show length only)
        assert_eq!(
            format_exif_value(&ExifValue::Undefined(vec![1, 2, 3, 4], 0)),
            "binary(4 bytes)"
        );

        // Test division by zero
        assert_eq!(
            format_exif_value(&ExifValue::Rational(vec![Rational { num: 1, denom: 0 }])),
            "undefined"
        );
    }

    #[test]
    fn test_extract_safe_exif_empty_data() {
        // Test with data that has no EXIF
        let empty_data = vec![0u8; 100];
        let result = extract_safe_exif(&empty_data);
        assert!(result.is_empty());

        // Test with empty data
        let result = extract_safe_exif(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_exif_security_validation_behavior() {
        // Test that extract_safe_exif returns empty map when security validation fails
        // We can't easily create malicious EXIF data in tests, but we can verify the behavior
        // by testing with empty/invalid data which should be handled safely

        // Test with completely invalid EXIF data
        let invalid_exif_data = vec![0xFF, 0xE1, 0x00, 0x16]; // Invalid EXIF header
        let result = extract_safe_exif(&invalid_exif_data);
        // Should return empty map for invalid data (safe fallback)
        assert!(result.is_empty());

        // Test with random binary data that might trigger security checks
        let random_data = vec![0u8; 50000]; // Large random data
        let result = extract_safe_exif(&random_data);
        // Should return empty map for unparseable data (safe fallback)
        assert!(result.is_empty());
    }

    #[test]
    fn test_process_image_metadata_dimension_validation() {
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
            cleaned_exif: HashMap::new(),
        };

        // Test with dimension preservation enabled, blurhash disabled
        let options = MediaProcessingOptions {
            preserve_dimensions: true,
            generate_blurhash: false,
            sanitize_exif: true,
            max_dimension: Some(100),
            max_file_size: None,
        };

        let result = process_image_metadata(&png_data, metadata.clone(), &options);
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

        let result = process_image_metadata(&png_data, metadata, &strict_options);
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
