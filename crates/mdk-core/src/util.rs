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

/// Checks if a string contains only hexadecimal characters
///
/// # Arguments
///
/// * `content` - The string to check
///
/// # Returns
///
/// `true` if the string contains only hex characters [0-9a-fA-F], `false` otherwise
#[inline]
pub(crate) fn is_hex_only(content: &str) -> bool {
    content.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decodes content from either base64 or hex encoding with accurate error reporting
///
/// Detects the format based on character set:
/// - Hex uses only: 0-9, a-f, A-F
/// - Base64 uses: A-Z, a-z, 0-9, +, /, =
///
/// If the string contains only hex characters, it attempts hex decoding first (legacy format).
/// If hex decoding fails or if the string contains non-hex characters, it attempts base64 decoding.
///
/// # Arguments
///
/// * `content` - The encoded string (base64 or hex)
/// * `label` - A label for the content type (e.g., "key package", "welcome") used in error messages
///
/// # Returns
///
/// A tuple of (decoded bytes, format description) on success, or an error message string
/// describing which decode attempts were made.
pub(crate) fn decode_dual_format(
    content: &str,
    label: &str,
) -> Result<(Vec<u8>, &'static str), String> {
    let hex_only = is_hex_only(content);

    if hex_only {
        // Try hex decode first (legacy format)
        if let Ok(bytes) = hex::decode(content) {
            return Ok((bytes, "hex (legacy format)"));
        }
    }

    // Decode as base64 (new format or fallback)
    match BASE64.decode(content) {
        Ok(bytes) => Ok((bytes, "base64 (new format)")),
        Err(e) => {
            // Accurate error message based on what was actually attempted
            if hex_only {
                Err(format!(
                    "Failed to decode {} (attempted hex and base64): {}",
                    label, e
                ))
            } else {
                Err(format!("Failed to decode {} as base64: {}", label, e))
            }
        }
    }
}
