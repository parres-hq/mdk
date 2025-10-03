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
        // Encode to hex
        let public_key: String = public_key.to_hex();

        let credential = BasicCredential::new(public_key.into());
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

        assert_eq!(
            relays_values.len(),
            2,
            "Should have exactly 2 relay URLs"
        );
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
}
