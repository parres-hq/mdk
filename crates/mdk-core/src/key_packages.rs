//! Nostr MLS Key Packages

use mdk_storage_traits::MdkStorageProvider;
use nostr::{Event, Kind, PublicKey, RelayUrl, Tag, TagKind};
use openmls::key_packages::KeyPackage;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::storage::StorageProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::MDK;
use crate::error::Error;

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

    /// Parse key package from [`Event`]
    pub fn parse_key_package(&self, event: &Event) -> Result<KeyPackage, Error> {
        if event.kind != Kind::MlsKeyPackage {
            return Err(Error::UnexpectedEvent {
                expected: Kind::MlsKeyPackage,
                received: event.kind,
            });
        }

        self.parse_serialized_key_package(&event.content)
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

    /// Test KeyPackage last resort extension presence and basic lifecycle (MIP-00)
    ///
    /// This test validates that KeyPackages include the last_resort extension by default
    /// and that basic KeyPackage lifecycle operations work correctly.
    ///
    /// Note: The last_resort extension signals that a KeyPackage CAN be reused by multiple
    /// group creators before the recipient processes any welcomes. However, once the recipient
    /// processes and accepts a welcome, the KeyPackage is consumed and deleted from storage.
    /// Testing true concurrent reuse would require more complex multi-device scenarios.
    ///
    /// Requirements tested:
    /// - KeyPackage includes last_resort extension
    /// - Signing key is retained after joining a group
    /// - User can successfully join a group using a KeyPackage
    /// - Key rotation proposals can be created after joining
    #[test]
    fn test_last_resort_keypackage_lifecycle() {
        use crate::test_util::create_nostr_group_config_data;
        use nostr::{EventBuilder, Keys};

        // Setup: Create Bob who will be invited to a group
        let bob_keys = Keys::generate();
        let bob_mdk = create_test_mdk();
        let bob_pubkey = bob_keys.public_key();

        // Setup: Create Alice who will create the group
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        // Step 1: Bob creates a KeyPackage with last_resort extension
        // Note: By default, MDK creates KeyPackages with last_resort extension enabled
        let relays = vec![RelayUrl::parse("wss://test.relay").unwrap()];
        let (bob_key_package_hex, tags) = bob_mdk
            .create_key_package_for_event(&bob_pubkey, relays.clone())
            .expect("Failed to create key package");

        // Verify last_resort extension is present in the tags
        let extensions_tag = tags
            .iter()
            .find(|t| t.kind() == TagKind::MlsExtensions)
            .expect("Extensions tag not found");
        let extension_ids: Vec<String> = extensions_tag
            .as_slice()
            .iter()
            .skip(1) // Skip tag name
            .map(|s| s.to_string())
            .collect();
        assert!(
            extension_ids.contains(&"0x000a".to_string()),
            "KeyPackage should include last_resort extension (0x000a)"
        );

        // Create the KeyPackage event
        let bob_key_package_event = EventBuilder::new(Kind::MlsKeyPackage, bob_key_package_hex)
            .tags(tags.to_vec())
            .sign_with_keys(&bob_keys)
            .expect("Failed to sign event");

        // Step 2: Alice creates a group and adds Bob using the KeyPackage
        let group_config = create_nostr_group_config_data(vec![alice_keys.public_key()]);
        let group_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package_event.clone()],
                group_config,
            )
            .expect("Failed to create group");

        // Alice merges the pending commit
        alice_mdk
            .merge_pending_commit(&group_result.group.mls_group_id)
            .expect("Failed to merge pending commit");

        // Step 3: Bob processes and accepts the welcome
        let welcome = &group_result.welcome_rumors[0];
        bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), welcome)
            .expect("Failed to process welcome");
        let pending_welcomes = bob_mdk
            .get_pending_welcomes()
            .expect("Failed to get pending welcomes");
        assert!(
            !pending_welcomes.is_empty(),
            "Bob should have pending welcomes after processing"
        );
        bob_mdk
            .accept_welcome(&pending_welcomes[0])
            .expect("Failed to accept welcome");

        // Verify Bob joined the group
        let bob_groups = bob_mdk.get_groups().expect("Failed to get Bob's groups");
        assert_eq!(
            bob_groups.len(),
            1,
            "Bob should have joined 1 group"
        );

        // Step 4: Verify Bob can send messages (validates signing key is retained)
        let group = &bob_groups[0];
        let rumor = crate::test_util::create_test_rumor(&bob_keys, "Test message");
        let message_result = bob_mdk.create_message(&group.mls_group_id, rumor);
        assert!(
            message_result.is_ok(),
            "Bob should be able to send messages (signing key retained)"
        );

        // Step 5: Verify key rotation can be performed
        let rotation_result = bob_mdk.self_update(&group.mls_group_id);
        assert!(
            rotation_result.is_ok(),
            "Bob should be able to rotate keys"
        );

        // Verify the rotation created a proposal
        let rotation_result_data = rotation_result.expect("Rotation should succeed");
        assert_eq!(
            rotation_result_data.evolution_event.kind,
            Kind::MlsGroupMessage,
            "Rotation should create a group message event"
        );

        // Note: Testing true concurrent KeyPackage reuse (multiple group creators using the same
        // KeyPackage before the recipient processes any welcomes) would require a more complex
        // test setup with careful timing control. The last_resort extension enables this at the
        // protocol level, but the current test validates the extension is present and basic
        // lifecycle works correctly.
    }
}

