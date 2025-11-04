use mdk_storage_traits::groups::types::GroupExporterSecret;
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
