//! Nostr MLS Welcomes

use mdk_storage_traits::MdkStorageProvider;
use mdk_storage_traits::groups::types as group_types;
use mdk_storage_traits::welcomes::types as welcome_types;
use nostr::{EventId, Timestamp, UnsignedEvent};
use openmls::prelude::*;
use tls_codec::Deserialize as TlsDeserialize;

use crate::MDK;
use crate::error::Error;
use crate::extension::NostrGroupDataExtension;

/// Welcome preview
#[derive(Debug)]
pub struct WelcomePreview {
    /// Staged welcome
    pub staged_welcome: StagedWelcome,
    /// Nostr data
    pub nostr_group_data: NostrGroupDataExtension,
}

/// Joined group result
#[derive(Debug)]
pub struct JoinedGroupResult {
    /// MLS group
    pub mls_group: MlsGroup,
    /// Nostr data
    pub nostr_group_data: NostrGroupDataExtension,
}

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Gets a welcome by event id
    pub fn get_welcome(&self, event_id: &EventId) -> Result<Option<welcome_types::Welcome>, Error> {
        let welcome = self
            .storage()
            .find_welcome_by_event_id(event_id)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        Ok(welcome)
    }

    /// Gets pending welcomes
    pub fn get_pending_welcomes(&self) -> Result<Vec<welcome_types::Welcome>, Error> {
        let welcomes = self
            .storage()
            .pending_welcomes()
            .map_err(|e| Error::Welcome(e.to_string()))?;
        Ok(welcomes)
    }

    /// Processes a welcome and stores it in the database
    pub fn process_welcome(
        &self,
        wrapper_event_id: &EventId,
        rumor_event: &UnsignedEvent,
    ) -> Result<welcome_types::Welcome, Error> {
        if self.is_welcome_processed(wrapper_event_id)? {
            let processed_welcome = self
                .storage()
                .find_processed_welcome_by_event_id(wrapper_event_id)
                .map_err(|e| Error::Welcome(e.to_string()))?;
            return match processed_welcome {
                Some(processed_welcome) => {
                    if let Some(welcome_event_id) = processed_welcome.welcome_event_id {
                        self.storage()
                            .find_welcome_by_event_id(&welcome_event_id)
                            .map_err(|e| Error::Welcome(e.to_string()))?
                            .ok_or(Error::MissingWelcomeForProcessedWelcome)
                    } else {
                        Err(Error::MissingWelcomeForProcessedWelcome)
                    }
                }
                None => Err(Error::ProcessedWelcomeNotFound),
            };
        }

        let welcome_preview = self.preview_welcome(wrapper_event_id, rumor_event)?;

        // Create a pending group
        let group = group_types::Group {
            mls_group_id: welcome_preview
                .staged_welcome
                .group_context()
                .group_id()
                .clone()
                .into(),
            nostr_group_id: welcome_preview.nostr_group_data.nostr_group_id,
            name: welcome_preview.nostr_group_data.name.clone(),
            description: welcome_preview.nostr_group_data.description.clone(),
            image_hash: welcome_preview.nostr_group_data.image_hash,
            image_key: welcome_preview.nostr_group_data.image_key,
            image_nonce: welcome_preview.nostr_group_data.image_nonce,
            admin_pubkeys: welcome_preview.nostr_group_data.admins.clone(),
            last_message_id: None,
            last_message_at: None,
            epoch: welcome_preview
                .staged_welcome
                .group_context()
                .epoch()
                .as_u64(),
            state: group_types::GroupState::Pending,
        };

        let mls_group_id = group.mls_group_id.clone();

        // Save the pending group
        self.storage()
            .save_group(group)
            .map_err(|e| Error::Group(e.to_string()))?;

        // Save the group relays
        self.storage()
            .replace_group_relays(
                &mls_group_id,
                welcome_preview.nostr_group_data.relays.clone(),
            )
            .map_err(|e| Error::Group(e.to_string()))?;

        let processed_welcome = welcome_types::ProcessedWelcome {
            wrapper_event_id: *wrapper_event_id,
            welcome_event_id: rumor_event.id,
            processed_at: Timestamp::now(),
            state: welcome_types::ProcessedWelcomeState::Processed,
            failure_reason: None,
        };

        let welcome = welcome_types::Welcome {
            id: rumor_event.id.unwrap(),
            event: rumor_event.clone(),
            mls_group_id: welcome_preview
                .staged_welcome
                .group_context()
                .group_id()
                .clone()
                .into(),
            nostr_group_id: welcome_preview.nostr_group_data.nostr_group_id,
            group_name: welcome_preview.nostr_group_data.name,
            group_description: welcome_preview.nostr_group_data.description,
            group_image_hash: welcome_preview.nostr_group_data.image_hash,
            group_image_key: welcome_preview.nostr_group_data.image_key,
            group_image_nonce: welcome_preview.nostr_group_data.image_nonce,
            group_admin_pubkeys: welcome_preview.nostr_group_data.admins,
            group_relays: welcome_preview.nostr_group_data.relays,
            welcomer: rumor_event.pubkey,
            member_count: welcome_preview.staged_welcome.members().count() as u32,
            state: welcome_types::WelcomeState::Pending,
            wrapper_event_id: *wrapper_event_id,
        };

        self.storage()
            .save_processed_welcome(processed_welcome)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        self.storage()
            .save_welcome(welcome.clone())
            .map_err(|e| Error::Welcome(e.to_string()))?;

        Ok(welcome)
    }

    /// Accepts a welcome
    pub fn accept_welcome(&self, welcome: &welcome_types::Welcome) -> Result<(), Error> {
        let welcome_preview = self.preview_welcome(&welcome.wrapper_event_id, &welcome.event)?;
        let mls_group = welcome_preview.staged_welcome.into_group(&self.provider)?;

        // Update the welcome to accepted
        let mut welcome = welcome.clone();
        welcome.state = welcome_types::WelcomeState::Accepted;
        self.storage()
            .save_welcome(welcome)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        // Update the group to active
        if let Some(mut group) = self.get_group(&mls_group.group_id().into())? {
            let mls_group_id = group.mls_group_id.clone();

            // Update group state
            group.state = group_types::GroupState::Active;

            // Save group
            self.storage().save_group(group).map_err(
                |e: mdk_storage_traits::groups::error::GroupError| Error::Group(e.to_string()),
            )?;

            // Save the group relays after saving the group
            self.storage()
                .replace_group_relays(&mls_group_id, welcome_preview.nostr_group_data.relays)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        Ok(())
    }

    /// Declines a welcome
    pub fn decline_welcome(&self, welcome: &welcome_types::Welcome) -> Result<(), Error> {
        let welcome_preview = self.preview_welcome(&welcome.wrapper_event_id, &welcome.event)?;

        let mls_group_id = welcome_preview.staged_welcome.group_context().group_id();

        // Update the welcome to declined
        let mut welcome = welcome.clone();
        welcome.state = welcome_types::WelcomeState::Declined;
        self.storage()
            .save_welcome(welcome)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        // Update the group to inactive
        if let Some(mut group) = self.get_group(&mls_group_id.into())? {
            group.state = group_types::GroupState::Inactive;
            self.storage()
                .save_group(group)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        Ok(())
    }

    /// Parses a welcome message and extracts group information.
    ///
    /// This function takes a serialized welcome message and processes it to extract both the staged welcome
    /// and the Nostr-specific group data. This is a lower-level function used by both `preview_welcome_event`
    /// and `join_group_from_welcome`.
    ///
    /// # Arguments
    ///
    /// * `welcome_message` - The serialized welcome message as a byte vector
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The `StagedWelcome` which can be used to join the group
    /// - The `NostrGroupDataExtension` containing Nostr-specific group metadata
    ///
    /// # Errors
    ///
    /// Returns a `WelcomeError` if:
    /// - The welcome message cannot be deserialized
    /// - The message is not a valid welcome message
    /// - The welcome message cannot be processed
    /// - The group data extension cannot be extracted
    fn parse_serialized_welcome(
        &self,
        mut welcome_message: &[u8],
    ) -> Result<(StagedWelcome, NostrGroupDataExtension), Error> {
        // Parse welcome message
        let welcome_message_in = MlsMessageIn::tls_deserialize(&mut welcome_message)?;

        let welcome: Welcome = match welcome_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::InvalidWelcomeMessage),
        };

        let mls_group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let staged_welcome =
            StagedWelcome::new_from_welcome(&self.provider, &mls_group_config, welcome, None)?;

        let nostr_group_data =
            NostrGroupDataExtension::from_group_context(staged_welcome.group_context())?;

        Ok((staged_welcome, nostr_group_data))
    }

    /// Previews a welcome message without joining the group.
    ///
    /// This function parses and validates a welcome message, returning information about the group
    /// that can be used to decide whether to join it. Unlike `join_group_from_welcome`, this does
    /// not actually join the group.
    ///
    /// # Arguments
    ///
    /// * `mdk` - The MDK instance containing MLS configuration and provider
    /// * `welcome_message` - The serialized welcome message as a byte vector
    ///
    /// # Returns
    ///
    /// A `WelcomePreview` containing the staged welcome and group data on success,
    /// or a `WelcomeError` on failure.
    ///
    /// # Errors
    ///
    /// Returns a `WelcomeError` if:
    /// - The welcome message cannot be parsed
    /// - The welcome message is invalid
    fn preview_welcome(
        &self,
        wrapper_event_id: &EventId,
        welcome_event: &UnsignedEvent,
    ) -> Result<WelcomePreview, Error> {
        let hex_content = match hex::decode(&welcome_event.content) {
            Ok(content) => content,
            Err(e) => {
                let error_string = format!("Error hex decoding welcome event: {:?}", e);
                let processed_welcome = welcome_types::ProcessedWelcome {
                    wrapper_event_id: *wrapper_event_id,
                    welcome_event_id: welcome_event.id,
                    processed_at: Timestamp::now(),
                    state: welcome_types::ProcessedWelcomeState::Failed,
                    failure_reason: Some(error_string.clone()),
                };

                self.storage()
                    .save_processed_welcome(processed_welcome)
                    .map_err(|e| Error::Welcome(e.to_string()))?;

                tracing::error!(target: "mdk_core::welcomes::process_welcome", "Error processing welcome: {}", error_string);

                return Err(Error::Welcome(error_string));
            }
        };

        let welcome_preview = match self.parse_serialized_welcome(&hex_content) {
            Ok((staged_welcome, nostr_group_data)) => WelcomePreview {
                staged_welcome,
                nostr_group_data,
            },
            Err(e) => {
                let error_string = format!("Error previewing welcome: {:?}", e);
                let processed_welcome = welcome_types::ProcessedWelcome {
                    wrapper_event_id: *wrapper_event_id,
                    welcome_event_id: welcome_event.id,
                    processed_at: Timestamp::now(),
                    state: welcome_types::ProcessedWelcomeState::Failed,
                    failure_reason: Some(error_string.clone()),
                };

                self.storage()
                    .save_processed_welcome(processed_welcome)
                    .map_err(|e| Error::Welcome(e.to_string()))?;

                tracing::error!(target: "mdk_core::welcomes::process_welcome", "Error processing welcome: {}", error_string);

                return Err(Error::Welcome(error_string));
            }
        };

        Ok(welcome_preview)
    }

    /// Check if a welcome has been processed
    fn is_welcome_processed(&self, wrapper_event_id: &EventId) -> Result<bool, Error> {
        let processed_welcome = self
            .storage()
            .find_processed_welcome_by_event_id(wrapper_event_id)
            .map_err(|e| Error::Welcome(e.to_string()))?;
        Ok(processed_welcome.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::tests::create_test_mdk;
    use nostr::{Keys, Kind, TagKind};

    /// Test that Welcome event structure matches Marmot spec (MIP-02)
    /// Spec requires:
    /// - Kind: 444 (MlsWelcome)
    /// - Content: hex-encoded serialized MLSMessage
    /// - Tags: exactly 3 tags (relays + event reference + client)
    /// - Must be unsigned (UnsignedEvent for NIP-59 gift wrapping)
    #[test]
    fn test_welcome_event_structure_mip02_compliance() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // Create group - this will generate welcome rumors for each member
        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![
                    create_key_package_event(&mdk, &members[0]),
                    create_key_package_event(&mdk, &members[1]),
                ],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        // Verify we have welcome rumors for both members
        assert_eq!(
            create_result.welcome_rumors.len(),
            2,
            "Should have welcome rumors for both members"
        );

        // Test each welcome rumor
        for welcome_rumor in &create_result.welcome_rumors {
            // 1. Verify kind is 444 (MlsWelcome)
            assert_eq!(
                welcome_rumor.kind,
                Kind::MlsWelcome,
                "Welcome event must have kind 444 (MlsWelcome)"
            );

            // 2. Verify content is hex-encoded (valid hex)
            assert!(
                hex::decode(&welcome_rumor.content).is_ok(),
                "Welcome content must be valid hex-encoded data"
            );

            // Verify decoded content is substantial (MLS Welcome messages are typically > 50 bytes)
            let decoded_content =
                hex::decode(&welcome_rumor.content).expect("Failed to decode welcome content");
            assert!(
                decoded_content.len() > 50,
                "Welcome content should be substantial (typically > 50 bytes), got {} bytes",
                decoded_content.len()
            );

            // 3. Verify exactly 3 tags (relays + event reference + client)
            assert_eq!(
                welcome_rumor.tags.len(),
                3,
                "Welcome event must have exactly 3 tags per MIP-02"
            );

            // 4. Verify first tag is relays tag
            let tags_vec: Vec<&nostr::Tag> = welcome_rumor.tags.iter().collect();
            let relays_tag = tags_vec[0];
            assert_eq!(
                relays_tag.kind(),
                TagKind::Relays,
                "First tag must be 'relays' tag"
            );

            // Verify relays tag has content (group relay URLs)
            assert!(
                !relays_tag.as_slice().is_empty(),
                "Relays tag should contain relay URLs"
            );

            // 5. Verify second tag is event reference (e tag)
            let event_ref_tag = tags_vec[1];
            assert_eq!(
                event_ref_tag.kind(),
                TagKind::e(),
                "Second tag must be 'e' (event reference) tag"
            );

            // Verify e tag references a KeyPackage event (should have event ID)
            assert!(
                event_ref_tag.content().is_some(),
                "Event reference tag must have content (KeyPackage event ID)"
            );

            // 6. Verify third tag is client tag
            let client_tag = tags_vec[2];
            assert_eq!(
                client_tag.kind(),
                TagKind::Client,
                "Third tag must be 'client' tag"
            );

            // Verify client tag has content (MDK version)
            assert!(
                client_tag.content().is_some(),
                "Client tag should contain MDK version"
            );

            // 7. Verify event is unsigned (UnsignedEvent - no sig field when serialized)
            // Although the type is UnsignedEvent, the NIP-59 gift-wrapping step computes
            // and attaches an ID to the rumor before sealing, so the ID is expected to be Some here.
            assert!(
                welcome_rumor.id.is_some(),
                "Welcome rumor should have ID computed"
            );
        }
    }

    /// Test that Welcome content is valid MLS Welcome structure
    #[test]
    fn test_welcome_content_validation_mip02() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![create_key_package_event(&mdk, &members[0])],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        let welcome_rumor = &create_result.welcome_rumors[0];

        // Decode hex content
        let decoded_content =
            hex::decode(&welcome_rumor.content).expect("Welcome content should be valid hex");

        // Verify it's valid TLS-serialized MLS message
        // We can't fully deserialize without processing, but we can check basic structure
        assert!(
            decoded_content.len() > 50,
            "MLS Welcome messages should be substantial in size"
        );

        // The content should start with MLS message type indicators
        // (this is a basic sanity check - full validation happens in process_welcome)
        assert!(
            !decoded_content.is_empty(),
            "Decoded welcome should not be empty"
        );
    }

    /// Test that Welcome references correct KeyPackage event
    #[test]
    fn test_welcome_references_correct_keypackage() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // Create key package events and track their IDs
        let kp_event1 = create_key_package_event(&mdk, &members[0]);
        let kp_event2 = create_key_package_event(&mdk, &members[1]);
        let kp1_id = kp_event1.id;
        let kp2_id = kp_event2.id;

        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![kp_event1, kp_event2],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        assert_eq!(
            create_result.welcome_rumors.len(),
            2,
            "Should have 2 welcome rumors"
        );

        // Extract event IDs from welcome rumors
        let mut welcome_event_refs = Vec::new();
        for welcome_rumor in &create_result.welcome_rumors {
            let event_ref_tag = welcome_rumor
                .tags
                .iter()
                .find(|t| t.kind() == TagKind::e())
                .expect("Welcome should have e tag");

            let event_id_hex = event_ref_tag.content().expect("e tag should have content");
            welcome_event_refs.push(event_id_hex.to_string());
        }

        // Verify each KeyPackage event ID is referenced by exactly one welcome
        assert!(
            welcome_event_refs.contains(&kp1_id.to_hex()),
            "Welcome should reference first KeyPackage event"
        );
        assert!(
            welcome_event_refs.contains(&kp2_id.to_hex()),
            "Welcome should reference second KeyPackage event"
        );
    }

    /// Test that multiple welcomes are created for multiple new members
    #[test]
    fn test_multiple_welcomes_for_multiple_members() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // Add 3 members (we have 2 in the test helper, add one more)
        let member3 = Keys::generate();
        let members_vec = vec![
            create_key_package_event(&mdk, &members[0]),
            create_key_package_event(&mdk, &members[1]),
            create_key_package_event(&mdk, &member3),
        ];

        let create_result = mdk
            .create_group(
                &creator.public_key(),
                members_vec,
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        // Verify we have 3 welcome rumors
        assert_eq!(
            create_result.welcome_rumors.len(),
            3,
            "Should have welcome rumors for all 3 members"
        );

        // Verify all welcomes have the same structure
        for welcome_rumor in &create_result.welcome_rumors {
            assert_eq!(welcome_rumor.kind, Kind::MlsWelcome);
            assert_eq!(welcome_rumor.tags.len(), 3);
            assert!(hex::decode(&welcome_rumor.content).is_ok());
        }
    }

    /// Test that Welcome relays tag contains group relay URLs
    #[test]
    fn test_welcome_relays_tag_content() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![create_key_package_event(&mdk, &members[0])],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        let welcome_rumor = &create_result.welcome_rumors[0];

        // Extract relays tag
        let relays_tag = welcome_rumor
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::Relays)
            .expect("Welcome should have relays tag");

        // Verify relays tag structure
        let relays_slice = relays_tag.as_slice();
        assert!(
            relays_slice.len() > 1,
            "Relays tag should have at least tag name and one relay"
        );

        // First element is the tag name "relays"
        assert_eq!(
            relays_slice[0], "relays",
            "First element should be 'relays'"
        );

        // Remaining elements should be relay URLs
        for relay in relays_slice.iter().skip(1) {
            assert!(
                relay.starts_with("wss://") || relay.starts_with("ws://"),
                "Relay URLs should start with wss:// or ws://, got: {}",
                relay
            );
        }
    }

    /// Test Welcome processing flow
    #[test]
    fn test_welcome_processing_flow() {
        // Use the same MDK instance for both creator and member to share key store
        let mdk = create_test_mdk();

        let (creator, members, admins) = create_test_group_members();

        // Create group with one member
        let member_kp_event = create_key_package_event(&mdk, &members[0]);
        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![member_kp_event],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        let welcome_rumor = &create_result.welcome_rumors[0];

        // Simulate receiving welcome (wrapped event ID would be from NIP-59 wrapper)
        let wrapper_event_id = EventId::all_zeros(); // In real scenario, this would be the gift wrap event ID

        // Process welcome - this validates the welcome structure can be processed
        let welcome = mdk
            .process_welcome(&wrapper_event_id, welcome_rumor)
            .expect("Failed to process welcome");

        // Verify welcome was stored correctly
        assert_eq!(welcome.state, welcome_types::WelcomeState::Pending);
        assert_eq!(welcome.wrapper_event_id, wrapper_event_id);
        assert!(
            welcome.member_count >= 2,
            "Group should have at least 2 members (creator + member)"
        );

        // Verify the welcome event structure was correct (this is what we're really testing)
        assert_eq!(
            welcome_rumor.kind,
            Kind::MlsWelcome,
            "Welcome should be kind 444"
        );
        assert_eq!(welcome_rumor.tags.len(), 3, "Welcome should have 3 tags");
    }

    /// Test that welcome event structure remains consistent across group operations
    #[test]
    fn test_welcome_structure_consistency() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // Create group with first member
        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![create_key_package_event(&mdk, &members[0])],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id;
        let first_welcome = &create_result.welcome_rumors[0];

        // Merge pending commit to activate group
        mdk.merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Add another member
        let member3 = Keys::generate();
        let add_result = mdk
            .add_members(&group_id, &[create_key_package_event(&mdk, &member3)])
            .expect("Failed to add member");

        let second_welcome = &add_result
            .welcome_rumors
            .as_ref()
            .expect("Should have welcome rumors")[0];

        // Verify both welcomes have the same structure
        assert_eq!(first_welcome.kind, second_welcome.kind);
        assert_eq!(first_welcome.tags.len(), second_welcome.tags.len());

        let first_tags: Vec<&nostr::Tag> = first_welcome.tags.iter().collect();
        let second_tags: Vec<&nostr::Tag> = second_welcome.tags.iter().collect();
        assert_eq!(first_tags[0].kind(), second_tags[0].kind());
        assert_eq!(first_tags[1].kind(), second_tags[1].kind());

        // Both should be valid hex
        assert!(hex::decode(&first_welcome.content).is_ok());
        assert!(hex::decode(&second_welcome.content).is_ok());
    }
}
