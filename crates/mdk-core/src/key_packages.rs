//! Nostr MLS Key Packages

use mdk_storage_traits::MdkStorageProvider;
use nostr::{Event, Kind, PublicKey, RelayUrl, Tag, TagKind};
use openmls::key_packages::KeyPackage;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::storage::StorageProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::MDK;
use crate::constant::{DEFAULT_CIPHERSUITE, REQUIRED_EXTENSIONS};
use crate::error::Error;
use crate::util::NostrTagFormat;

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Creates a key package for a Nostr event.
    ///
    /// This function generates a hex-encoded key package that is used as the content field of a kind:443 Nostr event.
    /// The key package contains the user's credential and capabilities required for MLS operations.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A hex-encoded string containing the serialized key package
    /// * A tuple of tags for the Nostr event
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * It fails to generate the credential and signature keypair
    /// * It fails to build the key package
    /// * It fails to serialize the key package
    pub fn create_key_package_for_event<I>(
        &self,
        public_key: &PublicKey,
        relays: I,
    ) -> Result<(String, [Tag; 4]), Error>
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        let (credential, signature_keypair) = self.generate_credential_with_key(public_key)?;

        let capabilities: Capabilities = self.capabilities();

        let key_package_bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .mark_as_last_resort()
            .build(
                self.ciphersuite,
                &self.provider,
                &signature_keypair,
                credential,
            )?;

        let key_package_serialized = key_package_bundle.key_package().tls_serialize_detached()?;

        let tags = [
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            Tag::custom(TagKind::MlsCiphersuite, [self.ciphersuite_value()]),
            Tag::custom(TagKind::MlsExtensions, self.extensions_value()),
            Tag::relays(relays),
        ];

        Ok((hex::encode(key_package_serialized), tags))
    }

    /// Parses and validates a hex-encoded key package.
    ///
    /// This function takes a hex-encoded key package string, decodes it, deserializes it into a
    /// KeyPackageIn object, and validates its signature, ciphersuite, and extensions.
    ///
    /// # Arguments
    ///
    /// * `key_package_hex` - A hex-encoded string containing the serialized key package
    ///
    /// # Returns
    ///
    /// A validated KeyPackage on success, or a Error on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The hex decoding fails
    /// * The TLS deserialization fails
    /// * The key package validation fails (invalid signature, ciphersuite, or extensions)
    fn parse_serialized_key_package(&self, key_package_hex: &str) -> Result<KeyPackage, Error> {
        let key_package_bytes = hex::decode(key_package_hex)?;

        let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_bytes.as_slice())?;

        // Validate the signature, ciphersuite, and extensions of the key package
        let key_package =
            key_package_in.validate(self.provider.crypto(), ProtocolVersion::Mls10)?;

        Ok(key_package)
    }

    /// Parses and validates an MLS KeyPackage from a Nostr event.
    ///
    /// This method performs comprehensive validation before deserializing the key package:
    /// 1. Verifies the event is of kind `MlsKeyPackage` (Kind 443)
    /// 2. Validates all required tags are present and correctly formatted per MIP-00:
    ///    - `mls_protocol_version`: Protocol version (e.g., "1.0")
    ///    - `mls_ciphersuite`: Must be "0x0001" (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    ///    - `mls_extensions`: Must include all required extensions (0x0003, 0x000a, 0x0002, 0xf2ee)
    /// 3. Deserializes the TLS-encoded key package from the event content
    ///
    /// # Arguments
    ///
    /// * `event` - A Nostr event of kind `MlsKeyPackage` containing the serialized key package
    ///
    /// # Returns
    ///
    /// * `Ok(KeyPackage)` - Successfully parsed and validated key package
    /// * `Err(Error::UnexpectedEvent)` - Event is not of kind `MlsKeyPackage`
    /// * `Err(Error::KeyPackage)` - Tag validation failed (missing tags, invalid format, or unsupported values)
    /// * `Err(Error)` - Deserialization failed (malformed TLS data)
    ///
    /// # Backward Compatibility
    ///
    /// This method accepts both MIP-00 compliant tags and legacy formats:
    /// - Legacy tag names without `mls_` prefix (for `ciphersuite` and `extensions` only)
    /// - Legacy ciphersuite values: "1" or "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    /// - Legacy extension values: string names like "RequiredCapabilities" or comma-separated format
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mdk_core::MDK;
    /// # use nostr::Event;
    /// # fn example(mdk: &MDK<impl mdk_storage_traits::MdkStorageProvider>, event: &Event) -> Result<(), Box<dyn std::error::Error>> {
    /// // Parse key package from a received Nostr event
    /// let key_package = mdk.parse_key_package(event)?;
    ///
    /// // Key package is now validated and ready to use for MLS operations
    /// println!("Parsed key package with cipher suite: {:?}", key_package.ciphersuite());
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_key_package(&self, event: &Event) -> Result<KeyPackage, Error> {
        if event.kind != Kind::MlsKeyPackage {
            return Err(Error::UnexpectedEvent {
                expected: Kind::MlsKeyPackage,
                received: event.kind,
            });
        }

        // Validate tags before parsing the key package
        self.validate_key_package_tags(event)?;

        self.parse_serialized_key_package(&event.content)
    }

    /// Validates that key package event tags match MIP-00 specification.
    ///
    /// This function checks that:
    /// - The event has the required tags (mls_protocol_version, mls_ciphersuite, mls_extensions)
    /// - Tag values are in the correct format and contain valid values
    /// - Supports backward compatibility with legacy formats
    ///
    /// # Arguments
    ///
    /// * `event` - The key package event to validate
    ///
    /// # Returns
    ///
    /// Ok(()) if validation succeeds, or an Error describing what's wrong
    fn validate_key_package_tags(&self, event: &Event) -> Result<(), Error> {
        // Check for protocol version tag (required)
        event
            .tags
            .iter()
            .find(|tag| self.is_protocol_version_tag(tag))
            .ok_or_else(|| {
                Error::KeyPackage("Missing required tag: mls_protocol_version".to_string())
            })?;

        // Check for ciphersuite tag (required) and validate
        let ciphersuite_tag = event
            .tags
            .iter()
            .find(|tag| self.is_ciphersuite_tag(tag))
            .ok_or_else(|| {
                Error::KeyPackage("Missing required tag: mls_ciphersuite".to_string())
            })?;
        self.validate_ciphersuite_tag(ciphersuite_tag)?;

        // Check for extensions tag (required) and validate
        let extensions_tag = event
            .tags
            .iter()
            .find(|tag| self.is_extensions_tag(tag))
            .ok_or_else(|| Error::KeyPackage("Missing required tag: mls_extensions".to_string()))?;
        self.validate_extensions_tag(extensions_tag)?;

        Ok(())
    }

    /// Checks if a tag is a protocol version tag (MIP-00).
    ///
    /// **SPEC-COMPLIANT**: "mls_protocol_version"
    fn is_protocol_version_tag(&self, tag: &Tag) -> bool {
        matches!(tag.kind(), TagKind::MlsProtocolVersion)
    }

    /// Checks if a tag is a ciphersuite tag (MIP-00 or legacy format).
    ///
    /// **SPEC-COMPLIANT**: "mls_ciphersuite"
    /// **LEGACY**: "ciphersuite" (TODO: Remove after migration period)
    fn is_ciphersuite_tag(&self, tag: &Tag) -> bool {
        matches!(tag.kind(), TagKind::MlsCiphersuite) ||
        // Legacy format without mls_ prefix
        // TODO: Remove legacy check after migration period (target: EOY 2025)
        (tag.as_slice().first().map(|s| s.as_str()) == Some("ciphersuite"))
    }

    /// Checks if a tag is an extensions tag (MIP-00 or legacy format).
    ///
    /// **SPEC-COMPLIANT**: "mls_extensions"
    /// **LEGACY**: "extensions" (TODO: Remove after migration period)
    fn is_extensions_tag(&self, tag: &Tag) -> bool {
        matches!(tag.kind(), TagKind::MlsExtensions) ||
        // Legacy format without mls_ prefix
        // TODO: Remove legacy check after migration period (target: EOY 2025)
        (tag.as_slice().first().map(|s| s.as_str()) == Some("extensions"))
    }

    /// Validates ciphersuite tag format and value.
    ///
    /// This delegates to either spec-compliant validation or legacy validation.
    fn validate_ciphersuite_tag(&self, tag: &Tag) -> Result<(), Error> {
        let values: Vec<&str> = tag.as_slice().iter().map(|s| s.as_str()).collect();

        // Skip the tag name (first element) and get the value
        let ciphersuite_value = values
            .get(1)
            .ok_or_else(|| Error::KeyPackage("Ciphersuite tag must have a value".to_string()))?;

        // Try spec-compliant validation first
        if ciphersuite_value.starts_with("0x") {
            return self.validate_ciphersuite_mip00(ciphersuite_value);
        }

        // Fall back to legacy format validation for backward compatibility
        // TODO: Remove legacy validation after migration period (target: EOY 2025)
        self.validate_ciphersuite_legacy(ciphersuite_value)
    }

    /// Validates MIP-00 spec-compliant ciphersuite format.
    ///
    /// **SPEC-COMPLIANT**: This is the correct format per MIP-00.
    /// Currently only accepts: "0x0001" (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    fn validate_ciphersuite_mip00(&self, ciphersuite_value: &str) -> Result<(), Error> {
        // Validate length
        if ciphersuite_value.len() != 6 {
            return Err(Error::KeyPackage(format!(
                "Ciphersuite hex value must be 6 characters (0xXXXX), got: {}",
                ciphersuite_value
            )));
        }

        // Verify format: "0x" prefix + 4 hex digits
        ciphersuite_value
            .strip_prefix("0x")
            .filter(|hex| hex.len() == 4 && hex.chars().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| {
                Error::KeyPackage(format!(
                    "Ciphersuite value must be 0x followed by 4 hex digits, got: {}",
                    ciphersuite_value
                ))
            })?;

        // Validate the actual value - must match DEFAULT_CIPHERSUITE
        let expected_hex = DEFAULT_CIPHERSUITE.to_nostr_tag();
        if ciphersuite_value.to_lowercase() != expected_hex.to_lowercase() {
            return Err(Error::KeyPackage(format!(
                "Unsupported ciphersuite: {}. Only {} (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) is supported",
                ciphersuite_value, expected_hex
            )));
        }

        Ok(())
    }

    /// Validates legacy ciphersuite formats for backward compatibility.
    ///
    /// **LEGACY**: These formats are deprecated and will be removed.
    /// TODO: Remove this method after migration period (target: EOY 2025)
    ///
    /// Accepts:
    /// - Numeric string: "1"
    /// - Name string: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    fn validate_ciphersuite_legacy(&self, ciphersuite_value: &str) -> Result<(), Error> {
        if ciphersuite_value.is_empty() {
            return Err(Error::KeyPackage(
                "Ciphersuite value cannot be empty".to_string(),
            ));
        }

        // Legacy numeric format: "1"
        if let Ok(numeric_value) = ciphersuite_value.parse::<u16>() {
            if numeric_value != 1 {
                return Err(Error::KeyPackage(format!(
                    "Unsupported ciphersuite numeric value: {}. Only 1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) is supported",
                    numeric_value
                )));
            }
            return Ok(());
        }

        // Legacy name format: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        let accepted_legacy_names = [
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519",
        ];

        if !accepted_legacy_names.contains(&ciphersuite_value) {
            return Err(Error::KeyPackage(format!(
                "Unsupported legacy ciphersuite: {}. Expected '1', '0x0001', or 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'",
                ciphersuite_value
            )));
        }

        Ok(())
    }

    /// Validates extensions tag format and values.
    ///
    /// This delegates to either spec-compliant validation or legacy validation.
    fn validate_extensions_tag(&self, tag: &Tag) -> Result<(), Error> {
        let values: Vec<&str> = tag.as_slice().iter().map(|s| s.as_str()).collect();

        // Skip the tag name (first element) and get extension values
        let extension_values: Vec<&str> = values.iter().skip(1).copied().collect();

        if extension_values.is_empty() {
            return Err(Error::KeyPackage(
                "Extensions tag must have at least one value".to_string(),
            ));
        }

        // Check if this is new format (all values start with 0x) or legacy format
        let is_new_format = extension_values.iter().all(|v| v.starts_with("0x"));

        if is_new_format {
            return self.validate_extensions_mip00(&extension_values);
        }

        // Fall back to legacy format validation for backward compatibility
        // TODO: Remove legacy validation after migration period (target: EOY 2025)
        self.validate_extensions_legacy(&extension_values)
    }

    /// Validates MIP-00 spec-compliant extensions format.
    ///
    /// **SPEC-COMPLIANT**: This is the correct format per MIP-00.
    /// Required extensions (as separate hex values):
    /// - 0x0003 (RequiredCapabilities)
    /// - 0x000a (LastResort)
    /// - 0x0002 (RatchetTree)
    /// - 0xf2ee (MarmotGroupData)
    fn validate_extensions_mip00(&self, extension_values: &[&str]) -> Result<(), Error> {
        // Validate format of each hex value
        for (idx, ext_value) in extension_values.iter().enumerate() {
            // Validate length
            if ext_value.len() != 6 {
                return Err(Error::KeyPackage(format!(
                    "Extension {} hex value must be 6 characters (0xXXXX), got: {}",
                    idx, ext_value
                )));
            }

            // Verify format: "0x" prefix + 4 hex digits
            ext_value
                .strip_prefix("0x")
                .filter(|hex| hex.len() == 4 && hex.chars().all(|c| c.is_ascii_hexdigit()))
                .ok_or_else(|| {
                    Error::KeyPackage(format!(
                        "Extension {} value must be 0x followed by 4 hex digits, got: {}",
                        idx, ext_value
                    ))
                })?;
        }

        // Validate that all required extensions are present
        // Convert our constant ExtensionType array to hex strings for comparison
        // Normalize extension values to lowercase for case-insensitive comparison
        let normalized_extensions: std::collections::HashSet<String> =
            extension_values.iter().map(|s| s.to_lowercase()).collect();

        for required_ext in REQUIRED_EXTENSIONS.iter() {
            let required_hex = required_ext.to_nostr_tag();
            if !normalized_extensions.contains(&required_hex) {
                let ext_name = match u16::from(*required_ext) {
                    0x0003 => "RequiredCapabilities",
                    0x000a => "LastResort",
                    0x0002 => "RatchetTree",
                    0xf2ee => "MarmotGroupData",
                    _ => "Unknown",
                };
                return Err(Error::KeyPackage(format!(
                    "Missing required extension: {} ({})",
                    required_hex, ext_name
                )));
            }
        }

        Ok(())
    }

    /// Validates legacy extensions formats for backward compatibility.
    ///
    /// **LEGACY**: These formats are deprecated and will be removed.
    /// TODO: Remove this method after migration period (target: EOY 2025)
    ///
    /// Accepts two formats:
    /// - Separate string values: ["RequiredCapabilities", "LastResort", "RatchetTree", "Unknown(62190)"]
    /// - Single comma-separated string: ["RequiredCapabilities,LastResort,RatchetTree,Unknown(62190)"]
    fn validate_extensions_legacy(&self, extension_values: &[&str]) -> Result<(), Error> {
        // Legacy format names
        const LEGACY_EXTENSION_NAMES: [&str; 4] = [
            "RequiredCapabilities",
            "LastResort",
            "RatchetTree",
            "Unknown(62190)", // 62190 decimal = 0xF2EE hex
        ];

        // Verify no empty values
        for (idx, ext_value) in extension_values.iter().enumerate() {
            if ext_value.is_empty() {
                return Err(Error::KeyPackage(format!(
                    "Extension {} value cannot be empty",
                    idx
                )));
            }
        }

        // Check format: single comma-separated string OR multiple separate values
        if extension_values.len() == 1 {
            // Single string format: should contain all required extension names
            let combined = extension_values[0];
            for legacy_name in LEGACY_EXTENSION_NAMES.iter() {
                if !combined.contains(legacy_name) {
                    return Err(Error::KeyPackage(format!(
                        "Missing required extension in legacy format: {}",
                        legacy_name
                    )));
                }
            }
        } else {
            // Multiple separate values: each should be a valid legacy name
            for required_name in LEGACY_EXTENSION_NAMES.iter() {
                if !extension_values.contains(required_name) {
                    return Err(Error::KeyPackage(format!(
                        "Missing required extension in legacy format: {}",
                        required_name
                    )));
                }
            }
        }

        Ok(())
    }

    /// Deletes a key package from the MLS provider's storage.
    /// TODO: Do we need to delete the encryption keys from the MLS storage provider?
    ///
    /// # Arguments
    ///
    /// * `key_package` - The key package to delete
    pub fn delete_key_package_from_storage(&self, key_package: &KeyPackage) -> Result<(), Error> {
        let hash_ref = key_package.hash_ref(self.provider.crypto())?;

        self.provider
            .storage()
            .delete_key_package(&hash_ref)
            .map_err(|e| Error::Provider(e.to_string()))?;

        Ok(())
    }

    /// Generates a credential with a key for MLS (Messaging Layer Security) operations.
    ///
    /// This function creates a new credential and associated signature key pair for use in MLS.
    /// It uses the default MDK configuration and stores the generated key pair in the
    /// crypto provider's storage.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The user's nostr pubkey
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `CredentialWithKey` - The generated credential along with its public key.
    /// * `SignatureKeyPair` - The generated signature key pair.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * It fails to generate a signature key pair.
    /// * It fails to store the signature key pair in the crypto provider's storage.
    pub(crate) fn generate_credential_with_key(
        &self,
        public_key: &PublicKey,
    ) -> Result<(CredentialWithKey, SignatureKeyPair), Error> {
        let public_key_bytes: Vec<u8> = public_key.to_bytes().to_vec();

        let credential = BasicCredential::new(public_key_bytes);
        let signature_keypair = SignatureKeyPair::new(self.ciphersuite.signature_algorithm())?;

        signature_keypair
            .store(self.provider.storage())
            .map_err(|e| Error::Provider(e.to_string()))?;

        Ok((
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keypair.public().into(),
            },
            signature_keypair,
        ))
    }

    /// Parses a public key from credential identity bytes with backwards compatibility.
    ///
    /// This function supports both the incorrect 64-byte UTF-8 encoded hex string format
    /// and the correct 32-byte raw format as specified in MIP-00.
    ///
    /// # Arguments
    ///
    /// * `identity_bytes` - The raw bytes from a BasicCredential's identity field
    ///
    /// # Returns
    ///
    /// * `Ok(PublicKey)` - The parsed public key
    /// * `Err(Error)` - If the identity bytes cannot be parsed in either format
    ///
    /// # Format Support
    ///
    /// - **32 bytes**: New format (raw public key bytes) - preferred
    /// - **64 bytes**: Legacy format (UTF-8 encoded hex string) - deprecated but supported
    pub(crate) fn parse_credential_identity(
        &self,
        identity_bytes: &[u8],
    ) -> Result<PublicKey, Error> {
        match identity_bytes.len() {
            32 => {
                // Correct format: raw 32 bytes
                PublicKey::from_slice(identity_bytes)
                    .map_err(|e| Error::KeyPackage(format!("Invalid 32-byte public key: {}", e)))
            }
            64 => {
                // Incorrect format: 64-byte UTF-8 encoded hex string
                let hex_str = std::str::from_utf8(identity_bytes).map_err(|e| {
                    Error::KeyPackage(format!("Invalid UTF-8 in legacy credential: {}", e))
                })?;
                PublicKey::from_hex(hex_str).map_err(|e| {
                    Error::KeyPackage(format!("Invalid hex in legacy credential: {}", e))
                })
            }
            _ => Err(Error::KeyPackage(format!(
                "Invalid credential identity length: {} (expected 32 or 64)",
                identity_bytes.len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use nostr::EventBuilder;

    use super::*;
    use crate::constant::DEFAULT_CIPHERSUITE;
    use crate::tests::create_test_mdk;

    #[test]
    fn test_key_package_creation_and_parsing() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        // Create key package
        let (key_package_hex, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays.clone())
            .expect("Failed to create key package");

        // Create new instance for parsing
        let parsing_mls = create_test_mdk();

        // Parse and validate the key package
        let key_package = parsing_mls
            .parse_serialized_key_package(&key_package_hex)
            .expect("Failed to parse key package");

        // Verify the key package has the expected properties
        assert_eq!(key_package.ciphersuite(), DEFAULT_CIPHERSUITE);

        assert_eq!(tags.len(), 4);
        assert_eq!(tags[0].kind(), TagKind::MlsProtocolVersion);
        assert_eq!(tags[1].kind(), TagKind::MlsCiphersuite);
        assert_eq!(tags[2].kind(), TagKind::MlsExtensions);
        assert_eq!(tags[3].kind(), TagKind::Relays);

        assert_eq!(
            tags[3].content().unwrap(),
            relays
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    /// Test that ciphersuite tag format matches Marmot spec (MIP-00)
    /// Spec requires: ["ciphersuite", "0x0001"]
    #[test]
    fn test_ciphersuite_tag_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        let (_, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays)
            .expect("Failed to create key package");

        // Find ciphersuite tag
        let ciphersuite_tag = tags
            .iter()
            .find(|t| t.kind() == TagKind::MlsCiphersuite)
            .expect("Ciphersuite tag not found");

        // Verify format: should be hex with 0x prefix
        let ciphersuite_value = ciphersuite_tag.content().unwrap();
        assert!(
            ciphersuite_value.starts_with("0x"),
            "Ciphersuite value should start with '0x', got: {}",
            ciphersuite_value
        );

        // For DEFAULT_CIPHERSUITE (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519), value is 0x0001
        assert_eq!(
            ciphersuite_value, "0x0001",
            "Expected ciphersuite '0x0001' per MIP-00 spec, got: {}",
            ciphersuite_value
        );
    }

    /// Test that extensions tag format matches Marmot spec (MIP-00)
    /// Spec requires: ["extensions", "0x0001", "0x0002", "0x0003", ...]
    /// Each extension ID should be a separate hex value with 0x prefix
    #[test]
    fn test_extensions_tag_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        let (_, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays)
            .expect("Failed to create key package");

        // Find extensions tag
        let extensions_tag = tags
            .iter()
            .find(|t| t.kind() == TagKind::MlsExtensions)
            .expect("Extensions tag not found");

        // Get all values (first value is the tag name "mls_extensions", rest are extension IDs)
        let tag_values: Vec<String> = extensions_tag
            .as_slice()
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Should have at least 5 elements: tag name + 4 extension IDs
        assert!(
            tag_values.len() >= 5,
            "Expected at least 5 values (tag name + 4 extensions), got: {}",
            tag_values.len()
        );

        // Skip first element (tag name) and verify all extension IDs are hex format
        let extension_ids = &tag_values[1..];
        for (i, ext_id) in extension_ids.iter().enumerate() {
            assert!(
                ext_id.starts_with("0x"),
                "Extension ID {} should start with '0x', got: {}",
                i,
                ext_id
            );
            assert!(
                ext_id.len() == 6, // "0x" + 4 hex digits
                "Extension ID {} should be 6 chars (0xXXXX), got: {} with length {}",
                i,
                ext_id,
                ext_id.len()
            );
        }

        // Verify expected extension IDs are present
        // 0x0003 = RequiredCapabilities
        // 0x000a = LastResort
        // 0x0002 = RatchetTree
        // 0xf2ee = MarmotGroupData
        assert!(
            extension_ids.contains(&"0x0003".to_string()),
            "Should contain RequiredCapabilities (0x0003)"
        );
        assert!(
            extension_ids.contains(&"0x000a".to_string()),
            "Should contain LastResort (0x000a)"
        );
        assert!(
            extension_ids.contains(&"0x0002".to_string()),
            "Should contain RatchetTree (0x0002)"
        );
        assert!(
            extension_ids.contains(&"0xf2ee".to_string()),
            "Should contain MarmotGroupData (0xf2ee)"
        );
    }

    /// Test that protocol version tag matches Marmot spec (MIP-00)
    /// Spec requires: ["mls_protocol_version", "1.0"]
    #[test]
    fn test_protocol_version_tag_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        let (_, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays)
            .expect("Failed to create key package");

        // Find protocol version tag
        let version_tag = tags
            .iter()
            .find(|t| t.kind() == TagKind::MlsProtocolVersion)
            .expect("Protocol version tag not found");

        let version_value = version_tag.content().unwrap();
        assert_eq!(
            version_value, "1.0",
            "Expected protocol version '1.0' per MIP-00 spec, got: {}",
            version_value
        );
    }

    /// Test complete tag structure matches Marmot spec (MIP-00)
    /// This is an integration test ensuring all tags work together correctly
    #[test]
    fn test_complete_tag_structure_mip00_compliance() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![
            RelayUrl::parse("wss://relay1.example.com").unwrap(),
            RelayUrl::parse("wss://relay2.example.com").unwrap(),
        ];

        let (_, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays.clone())
            .expect("Failed to create key package");

        // Verify we have exactly 4 required tags
        assert_eq!(tags.len(), 4, "Should have exactly 4 tags");

        // Verify tag order matches spec example
        assert_eq!(
            tags[0].kind(),
            TagKind::MlsProtocolVersion,
            "First tag should be mls_protocol_version"
        );
        assert_eq!(
            tags[1].kind(),
            TagKind::MlsCiphersuite,
            "Second tag should be ciphersuite"
        );
        assert_eq!(
            tags[2].kind(),
            TagKind::MlsExtensions,
            "Third tag should be extensions"
        );
        assert_eq!(
            tags[3].kind(),
            TagKind::Relays,
            "Fourth tag should be relays"
        );

        // Verify relays tag format
        let relays_tag = &tags[3];
        let relays_values: Vec<String> = relays_tag
            .as_slice()
            .iter()
            .skip(1) // Skip tag name "relays"
            .map(|s| s.to_string())
            .collect();

        assert_eq!(relays_values.len(), 2, "Should have exactly 2 relay URLs");
        assert!(
            relays_values.contains(&"wss://relay1.example.com".to_string()),
            "Should contain relay1"
        );
        assert!(
            relays_values.contains(&"wss://relay2.example.com".to_string()),
            "Should contain relay2"
        );
    }

    #[test]
    fn test_key_package_deletion() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        // Create and parse key package
        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, relays.clone())
            .expect("Failed to create key package");

        // Create new instance for parsing and deletion
        let deletion_mls = create_test_mdk();
        let key_package = deletion_mls
            .parse_serialized_key_package(&key_package_hex)
            .expect("Failed to parse key package");

        // Delete the key package
        deletion_mls
            .delete_key_package_from_storage(&key_package)
            .expect("Failed to delete key package");
    }

    #[test]
    fn test_invalid_key_package_parsing() {
        let mdk = create_test_mdk();

        // Try to parse invalid hex
        let result = mdk.parse_serialized_key_package("invalid hex");
        assert!(matches!(result, Err(Error::Hex(..))));

        // Try to parse valid hex but invalid key package
        let result = mdk.parse_serialized_key_package("deadbeef");
        assert!(matches!(result, Err(Error::Tls(..))));
    }

    #[test]
    fn test_credential_generation() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let result = mdk.generate_credential_with_key(&test_pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_credential_identity_backwards_compatibility() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        // Test new format: 32-byte raw format (what we now write)
        let raw_bytes = test_pubkey.to_bytes();
        assert_eq!(raw_bytes.len(), 32, "Raw public key should be 32 bytes");

        let parsed_from_raw = mdk
            .parse_credential_identity(&raw_bytes)
            .expect("Should parse 32-byte raw format");
        assert_eq!(
            parsed_from_raw, test_pubkey,
            "Parsed public key from raw bytes should match original"
        );

        // Test legacy format: 64-byte UTF-8 encoded hex string (what we used to write)
        let hex_string = test_pubkey.to_hex();
        let utf8_bytes = hex_string.as_bytes();
        assert_eq!(
            utf8_bytes.len(),
            64,
            "UTF-8 encoded hex string should be 64 bytes"
        );

        let parsed_from_legacy = mdk
            .parse_credential_identity(utf8_bytes)
            .expect("Should parse 64-byte legacy format");
        assert_eq!(
            parsed_from_legacy, test_pubkey,
            "Parsed public key from legacy format should match original"
        );

        // Verify both formats produce the same result
        assert_eq!(
            parsed_from_raw, parsed_from_legacy,
            "Both formats should parse to the same public key"
        );

        // Test invalid lengths
        let invalid_33_bytes = vec![0u8; 33];
        let result = mdk.parse_credential_identity(&invalid_33_bytes);
        assert!(
            matches!(result, Err(Error::KeyPackage(_))),
            "Should reject 33-byte input"
        );

        let invalid_63_bytes = vec![0u8; 63];
        let result = mdk.parse_credential_identity(&invalid_63_bytes);
        assert!(
            matches!(result, Err(Error::KeyPackage(_))),
            "Should reject 63-byte input"
        );

        // Test invalid UTF-8 in legacy format (64 bytes but not valid UTF-8)
        let invalid_utf8 = vec![0xFFu8; 64];
        let result = mdk.parse_credential_identity(&invalid_utf8);
        assert!(
            matches!(result, Err(Error::KeyPackage(_))),
            "Should reject invalid UTF-8 in legacy format"
        );

        // Test valid UTF-8 but invalid hex in legacy format
        let invalid_hex = b"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert_eq!(invalid_hex.len(), 64);
        let result = mdk.parse_credential_identity(invalid_hex);
        assert!(
            matches!(result, Err(Error::KeyPackage(_))),
            "Should reject invalid hex in legacy format"
        );
    }

    #[test]
    fn test_new_credentials_use_32_byte_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        // Generate a credential
        let (credential_with_key, _) = mdk
            .generate_credential_with_key(&test_pubkey)
            .expect("Should generate credential");

        // Extract the identity bytes
        let basic_credential = BasicCredential::try_from(credential_with_key.credential)
            .expect("Should extract basic credential");
        let identity_bytes = basic_credential.identity();

        // Verify it's using the new 32-byte format
        assert_eq!(
            identity_bytes.len(),
            32,
            "New credentials should use 32-byte raw format, not 64-byte UTF-8 encoded hex"
        );

        // Verify it's actually the raw bytes, not UTF-8 encoded hex
        let raw_bytes = test_pubkey.to_bytes();
        assert_eq!(
            identity_bytes, raw_bytes,
            "Identity should be raw public key bytes"
        );

        // Verify it's NOT the UTF-8 encoded hex string
        let hex_string = test_pubkey.to_hex();
        let utf8_bytes = hex_string.as_bytes();
        assert_ne!(
            identity_bytes, utf8_bytes,
            "Identity should NOT be UTF-8 encoded hex string"
        );
    }

    /// Test that valid key package events with correct MIP-00 tags are accepted
    #[test]
    fn test_validate_correct_mip00_tags() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        let (key_package_hex, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays)
            .expect("Failed to create key package");

        // Create an event with correct MIP-00 tags
        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(tags.to_vec())
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Validate tags - should succeed
        let result = mdk.validate_key_package_tags(&event);
        assert!(
            result.is_ok(),
            "Should accept valid MIP-00 tags, got error: {:?}",
            result
        );
    }

    /// Test that legacy tag format (without mls_ prefix) is still accepted for ciphersuite and extensions
    /// TODO: Remove this test after legacy format support is removed (target: EOY 2025)
    #[test]
    fn test_validate_legacy_tags_without_prefix() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Create event with legacy tag format (without mls_ prefix for ciphersuite and extensions)
        // Note: protocol_version was always correct in production, no legacy support needed
        let legacy_tags = vec![
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            Tag::custom(TagKind::custom("ciphersuite"), ["0x0001"]),
            Tag::custom(
                TagKind::custom("extensions"),
                ["0x0003", "0x000a", "0x0002", "0xf2ee"],
            ),
        ];

        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(legacy_tags)
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Validate tags - should succeed with legacy format
        let result = mdk.validate_key_package_tags(&event);
        assert!(
            result.is_ok(),
            "Should accept legacy tags without mls_ prefix (ciphersuite, extensions), got error: {:?}",
            result
        );
    }

    /// Test that legacy tag format with string values (not hex) is accepted (separate values)
    /// TODO: Remove this test after legacy format support is removed (target: EOY 2025)
    #[test]
    fn test_validate_legacy_tags_with_string_values() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Create event with legacy string values (not hex format) - separate values
        let legacy_tags = vec![
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            Tag::custom(
                TagKind::MlsCiphersuite,
                ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            ),
            Tag::custom(
                TagKind::MlsExtensions,
                [
                    "RequiredCapabilities",
                    "LastResort",
                    "RatchetTree",
                    "Unknown(62190)",
                ],
            ),
        ];

        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(legacy_tags)
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Validate tags - should succeed with legacy string format
        let result = mdk.validate_key_package_tags(&event);
        assert!(
            result.is_ok(),
            "Should accept legacy string format values (separate), got error: {:?}",
            result
        );
    }

    /// Test that legacy tag format with single comma-separated string is accepted
    /// TODO: Remove this test after legacy format support is removed (target: EOY 2025)
    #[test]
    fn test_validate_legacy_tags_with_comma_separated_string() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Create event with legacy single comma-separated string format
        let legacy_tags = vec![
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            Tag::custom(
                TagKind::MlsCiphersuite,
                ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            ),
            Tag::custom(
                TagKind::MlsExtensions,
                ["RequiredCapabilities,LastResort,RatchetTree,Unknown(62190)"], // Single string with commas
            ),
        ];

        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(legacy_tags)
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Validate tags - should succeed with legacy comma-separated format
        let result = mdk.validate_key_package_tags(&event);
        assert!(
            result.is_ok(),
            "Should accept legacy comma-separated string format, got error: {:?}",
            result
        );
    }

    /// Test that numeric ciphersuite format is accepted (e.g., "1" for 0x0001)
    /// TODO: Remove this test after legacy format support is removed (target: EOY 2025)
    #[test]
    fn test_validate_numeric_ciphersuite_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test numeric ciphersuite "1" (should map to 0x0001)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["1"]), // Numeric format
                Tag::custom(
                    TagKind::MlsExtensions,
                    ["0x0003", "0x000a", "0x0002", "0xf2ee"],
                ),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_ok(),
                "Should accept numeric ciphersuite '1', got error: {:?}",
                result
            );
        }

        // Test invalid numeric ciphersuite "2" (should be rejected)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["2"]), // Invalid numeric
                Tag::custom(
                    TagKind::MlsExtensions,
                    ["0x0003", "0x000a", "0x0002", "0xf2ee"],
                ),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject unsupported numeric ciphersuite '2'"
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Unsupported ciphersuite")
            );
        }
    }

    /// Test real-world example from production with numeric ciphersuite and comma-separated extensions
    /// TODO: Remove this test after legacy format support is removed (target: EOY 2025)
    #[test]
    fn test_validate_real_world_example() {
        let mdk = create_test_mdk();

        // Real key package content from production
        let key_package_hex = "0001000120bb8f754cb3b10edfaeb3853591ec45c44e6aee11b81f37dd0ea6a7184d300153201d1507624d5e3ab2a8df6019236e454ae42fb71a0f991373412f5a2ae541c150200e9ccae869886055bdfbfce5b2d2f5eef41cd5294ba6f903c1bb657503509f090001404035353262313062313831643537653063663162633333333532636637643137646564353861383135623234343230316437646263393338633661336566343063020001020001080003000a0002f2ee0002000101000000006909bca700000000697888b7004040a8c295c3f04e7f5212ea7f3265064acb28f3220e7634137c120f96916efa6623b8661f34611cfe82f7ea6176cb07b45b8b346f65a084a5013a9f92587fdeea0203000a004040f123560da089ae702d3cb311659a22a67dc038141eea235483f90a7cf62aa3233d4983074418d5dba1e4351d4a18d7174bab543e3dea8bd9c8bda23c28876b03";

        // Real tags from production: numeric ciphersuite "1" and comma-separated extensions
        let production_tags = vec![
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            Tag::custom(TagKind::MlsCiphersuite, ["1"]), // Numeric format from production
            Tag::custom(
                TagKind::MlsExtensions,
                ["RequiredCapabilities,LastResort,RatchetTree,Unknown(62190)"], // Comma-separated from production
            ),
            Tag::relays(vec![]), // Empty relays tag from production
        ];

        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(production_tags)
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Validate tags - should succeed with production format
        let result = mdk.validate_key_package_tags(&event);
        assert!(
            result.is_ok(),
            "Should accept real-world production format, got error: {:?}",
            result
        );

        // Also verify we can parse the full key package
        let parse_result = mdk.parse_key_package(&event);
        assert!(
            parse_result.is_ok(),
            "Should parse real-world key package, got error: {:?}",
            parse_result
        );
    }

    /// Test that missing required tags are rejected
    #[test]
    fn test_validate_missing_required_tags() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test missing protocol version
        {
            let tags = vec![
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", "0x000a"]),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject event without protocol_version tag"
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("mls_protocol_version")
            );
        }

        // Test missing ciphersuite
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", "0x000a"]),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject event without ciphersuite tag"
            );
            assert!(result.unwrap_err().to_string().contains("mls_ciphersuite"));
        }

        // Test missing extensions
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject event without extensions tag"
            );
            assert!(result.unwrap_err().to_string().contains("mls_extensions"));
        }
    }

    /// Test that invalid hex format in ciphersuite is rejected
    #[test]
    fn test_validate_invalid_ciphersuite_hex_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test invalid hex length (too short)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x01"]), // Too short
                Tag::custom(TagKind::MlsExtensions, ["0x0003"]),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject ciphersuite with invalid hex length"
            );
            assert!(result.unwrap_err().to_string().contains("6 characters"));
        }

        // Test invalid hex characters
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0xGGGG"]), // Invalid hex
                Tag::custom(TagKind::MlsExtensions, ["0x0003"]),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject ciphersuite with invalid hex characters"
            );
            assert!(result.unwrap_err().to_string().contains("4 hex digits"));
        }

        // Test empty ciphersuite value
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, [""]), // Empty value
                Tag::custom(TagKind::MlsExtensions, ["0x0003"]),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(result.is_err(), "Should reject empty ciphersuite value");
            assert!(result.unwrap_err().to_string().contains("cannot be empty"));
        }
    }

    /// Test that invalid hex format in extensions is rejected
    #[test]
    fn test_validate_invalid_extensions_hex_format() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test invalid hex length in extensions
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x03", "0x000a"]), // First one too short
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject extension with invalid hex length"
            );
            assert!(result.unwrap_err().to_string().contains("6 characters"));
        }

        // Test invalid hex characters in extensions
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", "0xZZZZ"]), // Invalid hex
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject extension with invalid hex characters"
            );
            assert!(result.unwrap_err().to_string().contains("4 hex digits"));
        }

        // Test empty extension value
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", ""]), // Empty value
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(result.is_err(), "Should reject empty extension value");
            assert!(result.unwrap_err().to_string().contains("cannot be empty"));
        }
    }

    /// Test that invalid ciphersuite values are rejected
    #[test]
    fn test_validate_invalid_ciphersuite_values() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test unsupported ciphersuite in hex format
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0002"]), // Unsupported ciphersuite
                Tag::custom(
                    TagKind::MlsExtensions,
                    ["0x0003", "0x000a", "0x0002", "0xf2ee"],
                ),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject unsupported ciphersuite 0x0002"
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Unsupported ciphersuite")
            );
        }

        // Test unsupported ciphersuite in legacy string format
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(
                    TagKind::MlsCiphersuite,
                    ["MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448"],
                ), // Unsupported
                Tag::custom(
                    TagKind::MlsExtensions,
                    [
                        "RequiredCapabilities",
                        "LastResort",
                        "RatchetTree",
                        "Unknown(62190)",
                    ],
                ),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject unsupported legacy ciphersuite"
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Unsupported legacy ciphersuite")
            );
        }
    }

    /// Test that missing required extensions are rejected
    #[test]
    fn test_validate_missing_required_extensions() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test missing RequiredCapabilities (0x0003)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x000a", "0x0002", "0xf2ee"]), // Missing 0x0003
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject event missing RequiredCapabilities"
            );
            assert!(result.unwrap_err().to_string().contains("0x0003"));
        }

        // Test missing LastResort (0x000a)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", "0x0002", "0xf2ee"]), // Missing 0x000a
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(result.is_err(), "Should reject event missing LastResort");
            assert!(result.unwrap_err().to_string().contains("0x000a"));
        }

        // Test missing RatchetTree (0x0002)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", "0x000a", "0xf2ee"]), // Missing 0x0002
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(result.is_err(), "Should reject event missing RatchetTree");
            assert!(result.unwrap_err().to_string().contains("0x0002"));
        }

        // Test missing MarmotGroupData (0xf2ee)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(TagKind::MlsCiphersuite, ["0x0001"]),
                Tag::custom(TagKind::MlsExtensions, ["0x0003", "0x000a", "0x0002"]), // Missing 0xf2ee
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject event missing MarmotGroupData"
            );
            assert!(result.unwrap_err().to_string().contains("0xf2ee"));
        }
    }

    /// Test that missing required extensions in legacy format are rejected
    #[test]
    fn test_validate_missing_legacy_extensions() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Test missing RequiredCapabilities in legacy format (separate values)
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(
                    TagKind::MlsCiphersuite,
                    ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                ),
                Tag::custom(
                    TagKind::MlsExtensions,
                    ["LastResort", "RatchetTree", "Unknown(62190)"], // Missing RequiredCapabilities
                ),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex.clone())
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject legacy format missing RequiredCapabilities"
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("RequiredCapabilities")
            );
        }

        // Test missing extension in legacy single-string format
        {
            let tags = vec![
                Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
                Tag::custom(
                    TagKind::MlsCiphersuite,
                    ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                ),
                Tag::custom(
                    TagKind::MlsExtensions,
                    ["RequiredCapabilities,LastResort,RatchetTree"], // Missing Unknown(62190)
                ),
            ];

            let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
                .tags(tags)
                .sign_with_keys(&nostr::Keys::generate())
                .unwrap();

            let result = mdk.validate_key_package_tags(&event);
            assert!(
                result.is_err(),
                "Should reject legacy single-string format missing extension"
            );
            assert!(result.unwrap_err().to_string().contains("Unknown(62190)"));
        }
    }

    /// Test parsing a complete key package event with valid MIP-00 tags
    #[test]
    fn test_parse_key_package_with_valid_tags() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();
        let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

        let (key_package_hex, tags) = mdk
            .create_key_package_for_event(&test_pubkey, relays)
            .expect("Failed to create key package");

        // Create an event with correct MIP-00 tags
        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(tags.to_vec())
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Parse key package - should succeed
        let result = mdk.parse_key_package(&event);
        assert!(
            result.is_ok(),
            "Should parse key package with valid MIP-00 tags, got error: {:?}",
            result
        );
    }

    /// Test parsing a key package event with legacy tags
    /// TODO: Remove this test after legacy format support is removed (target: EOY 2025)
    #[test]
    fn test_parse_key_package_with_legacy_tags() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Create event with legacy tag format (without mls_ prefix for ciphersuite/extensions, string values)
        // Note: protocol_version was always correct, no legacy support needed
        let legacy_tags = vec![
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            Tag::custom(
                TagKind::custom("ciphersuite"),
                ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            ),
            Tag::custom(
                TagKind::custom("extensions"),
                [
                    "RequiredCapabilities",
                    "LastResort",
                    "RatchetTree",
                    "Unknown(62190)",
                ],
            ),
        ];

        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(legacy_tags)
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Parse key package - should succeed with legacy format
        let result = mdk.parse_key_package(&event);
        assert!(
            result.is_ok(),
            "Should parse key package with legacy tags, got error: {:?}",
            result
        );
    }

    /// Test that parsing fails when required tags are missing
    #[test]
    fn test_parse_key_package_fails_with_missing_tags() {
        let mdk = create_test_mdk();
        let test_pubkey =
            PublicKey::from_hex("884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6")
                .unwrap();

        let (key_package_hex, _) = mdk
            .create_key_package_for_event(&test_pubkey, vec![])
            .expect("Failed to create key package");

        // Create event with missing tags
        let incomplete_tags = vec![
            Tag::custom(TagKind::MlsProtocolVersion, ["1.0"]),
            // Missing ciphersuite and extensions
        ];

        let event = EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
            .tags(incomplete_tags)
            .sign_with_keys(&nostr::Keys::generate())
            .unwrap();

        // Parse key package - should fail
        let result = mdk.parse_key_package(&event);
        assert!(
            result.is_err(),
            "Should fail to parse key package with missing required tags"
        );
        assert!(result.unwrap_err().to_string().contains("Missing required"));
    }
}
