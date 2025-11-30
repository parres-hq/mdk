use mdk_storage_traits::groups::types::GroupExporterSecret;
use nostr::base64::Engine;
use nostr::base64::engine::general_purpose::STANDARD as BASE64;
use nostr::nips::nip44;
use nostr::{Keys, SecretKey};
use openmls::prelude::{Ciphersuite, ExtensionType};

use crate::Error;

/// Trait for formatting MLS types as Nostr tag values
///
/// This trait provides a consistent way to format MLS types (Ciphersuite, ExtensionType)
/// as hex strings for use in Nostr tags. The format is always "0x" followed by 4 lowercase
/// hex digits.
pub(crate) trait NostrTagFormat {
    /// Convert to Nostr tag hex format (e.g., "0x0001")
    fn to_nostr_tag(&self) -> String;
}

impl NostrTagFormat for Ciphersuite {
    fn to_nostr_tag(&self) -> String {
        format!("0x{:04x}", u16::from(*self))
    }
}

impl NostrTagFormat for ExtensionType {
    fn to_nostr_tag(&self) -> String {
        format!("0x{:04x}", u16::from(*self))
    }
}

pub(crate) fn decrypt_with_exporter_secret(
    secret: &GroupExporterSecret,
    encrypted_content: &str,
) -> Result<Vec<u8>, Error> {
    // Convert that secret to nostr keys
    let secret_key: SecretKey = SecretKey::from_slice(&secret.secret)?;
    let export_nostr_keys = Keys::new(secret_key);

    // Decrypt message
    let message_bytes: Vec<u8> = nip44::decrypt_to_bytes(
        export_nostr_keys.secret_key(),
        &export_nostr_keys.public_key,
        encrypted_content,
    )?;

    Ok(message_bytes)
}

/// Encodes content using base64 with version tag, or hex without version tag
///
/// # Arguments
///
/// * `bytes` - The bytes to encode
/// * `use_base64` - If true, encode as base64 with "v1:" prefix; otherwise encode as hex
///
/// # Returns
///
/// The encoded string
pub(crate) fn encode_content(bytes: &[u8], use_base64: bool) -> String {
    if use_base64 {
        format!("v1:{}", BASE64.encode(bytes))
    } else {
        hex::encode(bytes)
    }
}

/// Decodes content from versioned base64 or legacy hex encoding
///
/// Supports two formats:
/// - **Version 1 (base64)**: Prefix "v1:" followed by base64-encoded content
/// - **Legacy (hex)**: No prefix, hex-encoded content
///
/// This version-based approach eliminates ambiguity when hex-only strings could be valid
/// in both formats (e.g., "deadbeef" is valid hex and valid base64, but decodes to
/// completely different bytes in each format).
///
/// # Arguments
///
/// * `content` - The encoded string (either "v1:base64data" or "hexdata")
/// * `label` - A label for the content type (e.g., "key package", "welcome") used in error messages
///
/// # Returns
///
/// A tuple of (decoded bytes, format description) on success, or an error message string.
pub(crate) fn decode_dual_format(
    content: &str,
    label: &str,
) -> Result<(Vec<u8>, &'static str), String> {
    // Check for version 1 prefix
    if let Some(b64_content) = content.strip_prefix("v1:") {
        // Version 1: base64 format
        return BASE64
            .decode(b64_content)
            .map(|bytes| (bytes, "base64 (v1)"))
            .map_err(|e| format!("Failed to decode {} as base64 (v1): {}", label, e));
    }

    // No version prefix: legacy hex format
    hex::decode(content)
        .map(|bytes| (bytes, "hex (legacy)"))
        .map_err(|e| format!("Failed to decode {} as hex (legacy): {}", label, e))
}
