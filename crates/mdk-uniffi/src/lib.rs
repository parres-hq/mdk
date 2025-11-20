//! UniFFI bindings for mdk-core with SQLite storage
//!
//! This crate provides foreign language bindings for mdk-core using UniFFI.
//! It wraps the MDK core functionality with SQLite storage backend.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use mdk_core::{
    Error as MdkError, MDK,
    extension::group_image::{
        decrypt_group_image as core_decrypt_group_image,
        derive_upload_keypair as core_derive_upload_keypair,
        prepare_group_image_for_upload as core_prepare_group_image_for_upload,
    },
    groups::{NostrGroupConfigData, NostrGroupDataUpdate},
    messages::MessageProcessingResult,
};
use mdk_sqlite_storage::MdkSqliteStorage;
use mdk_storage_traits::{
    GroupId, groups::types as group_types, messages::types as message_types,
    welcomes::types as welcome_types,
};
use nostr::{Event, EventBuilder, EventId, Kind, PublicKey, RelayUrl, TagKind, UnsignedEvent};
use std::path::PathBuf;
use std::sync::Mutex;

uniffi::setup_scaffolding!();

/// Main MDK instance with SQLite storage
#[derive(uniffi::Object)]
pub struct Mdk {
    mdk: Mutex<MDK<MdkSqliteStorage>>,
}

/// Error type for MDK UniFFI operations
#[derive(uniffi::Enum, Debug, thiserror::Error)]
pub enum MdkUniffiError {
    /// Storage-related error
    #[error("Storage error: {0}")]
    Storage(String),
    /// MDK core error
    #[error("MDK error: {0}")]
    Mdk(String),
    /// Invalid input parameter error
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<mdk_sqlite_storage::error::Error> for MdkUniffiError {
    fn from(err: mdk_sqlite_storage::error::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<MdkError> for MdkUniffiError {
    fn from(err: MdkError) -> Self {
        Self::Mdk(err.to_string())
    }
}

// Helper functions

fn parse_group_id(hex: &str) -> Result<GroupId, MdkUniffiError> {
    hex::decode(hex)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid group ID hex: {e}")))
        .map(|bytes| GroupId::from_slice(&bytes))
}

fn parse_event_id(hex: &str) -> Result<EventId, MdkUniffiError> {
    EventId::from_hex(hex)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid event ID: {e}")))
}

fn parse_public_key(hex: &str) -> Result<PublicKey, MdkUniffiError> {
    PublicKey::from_hex(hex)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid public key: {e}")))
}

fn parse_relay_urls(relays: &[String]) -> Result<Vec<RelayUrl>, MdkUniffiError> {
    relays
        .iter()
        .map(|r| RelayUrl::parse(r))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid relay URL: {e}")))
}

fn parse_json<T: serde::de::DeserializeOwned>(
    json: &str,
    context: &str,
) -> Result<T, MdkUniffiError> {
    serde_json::from_str(json)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Invalid {context}: {e}")))
}

impl Mdk {
    /// Lock the internal MDK instance for exclusive access.
    /// Panics if the mutex is poisoned (should never happen if using MDK correctly (do NOT share memory across threads)).
    fn lock(&self) -> std::sync::MutexGuard<'_, MDK<MdkSqliteStorage>> {
        self.mdk.lock().expect("MDK mutex poisoned")
    }
}

/// Create a new MDK instance with SQLite storage
#[uniffi::export]
pub fn new_mdk(db_path: String) -> Result<Mdk, MdkUniffiError> {
    let storage = MdkSqliteStorage::new(PathBuf::from(db_path))?;
    let mdk = MDK::new(storage);
    Ok(Mdk {
        mdk: Mutex::new(mdk),
    })
}

#[uniffi::export]
impl Mdk {
    /// Create a key package for a Nostr event
    pub fn create_key_package_for_event(
        &self,
        public_key: String,
        relays: Vec<String>,
    ) -> Result<KeyPackageResult, MdkUniffiError> {
        let pubkey = parse_public_key(&public_key)?;
        let relay_urls = parse_relay_urls(&relays)?;

        let mdk = self.lock();
        let (key_package_hex, tags) = mdk.create_key_package_for_event(&pubkey, relay_urls)?;

        let tags: Vec<Vec<String>> = tags.iter().map(|tag| tag.as_slice().to_vec()).collect();

        Ok(KeyPackageResult {
            key_package: key_package_hex,
            tags,
        })
    }

    /// Parse a key package from a Nostr event
    pub fn parse_key_package(&self, event_json: String) -> Result<(), MdkUniffiError> {
        let event: Event = parse_json(&event_json, "event JSON")?;
        self.lock().parse_key_package(&event)?;
        Ok(())
    }

    /// Get all groups
    pub fn get_groups(&self) -> Result<Vec<Group>, MdkUniffiError> {
        Ok(self
            .lock()
            .get_groups()?
            .into_iter()
            .map(Group::from)
            .collect())
    }

    /// Get a group by MLS group ID
    pub fn get_group(&self, mls_group_id: String) -> Result<Option<Group>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self.lock().get_group(&group_id)?.map(Group::from))
    }

    /// Get members of a group
    pub fn get_members(&self, mls_group_id: String) -> Result<Vec<String>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self
            .lock()
            .get_members(&group_id)?
            .into_iter()
            .map(|pk| pk.to_hex())
            .collect())
    }

    /// Get messages for a group
    pub fn get_messages(&self, mls_group_id: String) -> Result<Vec<Message>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self
            .lock()
            .get_messages(&group_id)?
            .into_iter()
            .map(Message::from)
            .collect())
    }

    /// Get a message by event ID
    pub fn get_message(&self, event_id: String) -> Result<Option<Message>, MdkUniffiError> {
        let event_id = parse_event_id(&event_id)?;
        Ok(self.lock().get_message(&event_id)?.map(Message::from))
    }

    /// Get pending welcomes
    pub fn get_pending_welcomes(&self) -> Result<Vec<Welcome>, MdkUniffiError> {
        Ok(self
            .lock()
            .get_pending_welcomes()?
            .into_iter()
            .map(Welcome::from)
            .collect())
    }

    /// Get a welcome by event ID
    pub fn get_welcome(&self, event_id: String) -> Result<Option<Welcome>, MdkUniffiError> {
        let event_id = parse_event_id(&event_id)?;
        Ok(self.lock().get_welcome(&event_id)?.map(Welcome::from))
    }

    /// Process a welcome message
    pub fn process_welcome(
        &self,
        wrapper_event_id: String,
        rumor_event_json: String,
    ) -> Result<Welcome, MdkUniffiError> {
        let wrapper_id = parse_event_id(&wrapper_event_id)?;
        let rumor_event: UnsignedEvent = parse_json(&rumor_event_json, "rumor event JSON")?;
        Ok(Welcome::from(
            self.lock().process_welcome(&wrapper_id, &rumor_event)?,
        ))
    }

    /// Accept a welcome message
    pub fn accept_welcome(&self, welcome_json: String) -> Result<(), MdkUniffiError> {
        let welcome: welcome_types::Welcome = parse_json(&welcome_json, "welcome JSON")?;
        self.lock().accept_welcome(&welcome)?;
        Ok(())
    }

    /// Decline a welcome message
    pub fn decline_welcome(&self, welcome_json: String) -> Result<(), MdkUniffiError> {
        let welcome: welcome_types::Welcome = parse_json(&welcome_json, "welcome JSON")?;
        self.lock().decline_welcome(&welcome)?;
        Ok(())
    }

    /// Get relays for a group
    pub fn get_relays(&self, mls_group_id: String) -> Result<Vec<String>, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        Ok(self
            .lock()
            .get_relays(&group_id)?
            .into_iter()
            .map(|r| r.to_string())
            .collect())
    }

    /// Create a new group
    pub fn create_group(
        &self,
        creator_public_key: String,
        member_key_package_events_json: Vec<String>,
        name: String,
        description: String,
        relays: Vec<String>,
        admins: Vec<String>,
    ) -> Result<CreateGroupResult, MdkUniffiError> {
        let creator_pubkey = parse_public_key(&creator_public_key)?;
        let relay_urls = parse_relay_urls(&relays)?;
        let admin_pubkeys: Result<Vec<PublicKey>, _> =
            admins.iter().map(|a| parse_public_key(a)).collect();
        let admin_pubkeys = admin_pubkeys?;

        let member_key_package_events: Result<Vec<Event>, _> = member_key_package_events_json
            .iter()
            .map(|json| parse_json(json, "key package event JSON"))
            .collect();
        let member_key_package_events = member_key_package_events?;

        let config = NostrGroupConfigData::new(
            name,
            description,
            None, // image_hash
            None, // image_key
            None, // image_nonce
            relay_urls,
            admin_pubkeys,
        );

        let mdk = self.lock();
        let result = mdk.create_group(&creator_pubkey, member_key_package_events, config)?;

        let welcome_rumors_json: Vec<String> = result
            .welcome_rumors
            .iter()
            .map(|rumor| {
                serde_json::to_string(rumor).map_err(|e| {
                    MdkUniffiError::InvalidInput(format!("Failed to serialize welcome rumor: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CreateGroupResult {
            group: Group::from(result.group),
            welcome_rumors_json,
        })
    }

    /// Add members to a group
    pub fn add_members(
        &self,
        mls_group_id: String,
        key_package_events_json: Vec<String>,
    ) -> Result<AddMembersResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;

        let key_package_events: Result<Vec<Event>, _> = key_package_events_json
            .iter()
            .map(|json| parse_json(json, "key package event JSON"))
            .collect();
        let key_package_events = key_package_events?;

        let mdk = self.lock();
        let result = mdk.add_members(&group_id, &key_package_events)?;

        let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
            MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
        })?;

        let welcome_rumors_json: Option<Vec<String>> = result
            .welcome_rumors
            .map(|rumors| {
                rumors
                    .iter()
                    .map(|rumor| {
                        serde_json::to_string(rumor).map_err(|e| {
                            MdkUniffiError::InvalidInput(format!(
                                "Failed to serialize welcome rumor: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(AddMembersResult {
            evolution_event_json,
            welcome_rumors_json,
            mls_group_id: hex::encode(result.mls_group_id.as_slice()),
        })
    }

    /// Remove members from a group
    pub fn remove_members(
        &self,
        mls_group_id: String,
        member_public_keys: Vec<String>,
    ) -> Result<AddMembersResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;

        let pubkeys: Result<Vec<PublicKey>, _> = member_public_keys
            .iter()
            .map(|pk| parse_public_key(pk))
            .collect();
        let pubkeys = pubkeys?;

        let mdk = self.lock();
        let result = mdk.remove_members(&group_id, &pubkeys)?;

        let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
            MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
        })?;

        let welcome_rumors_json: Option<Vec<String>> = result
            .welcome_rumors
            .map(|rumors| {
                rumors
                    .iter()
                    .map(|rumor| {
                        serde_json::to_string(rumor).map_err(|e| {
                            MdkUniffiError::InvalidInput(format!(
                                "Failed to serialize welcome rumor: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(AddMembersResult {
            evolution_event_json,
            welcome_rumors_json,
            mls_group_id: hex::encode(result.mls_group_id.as_slice()),
        })
    }

    /// Merge pending commit for a group
    pub fn merge_pending_commit(&self, mls_group_id: String) -> Result<(), MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        self.lock().merge_pending_commit(&group_id)?;
        Ok(())
    }

    /// Sync group metadata from MLS
    pub fn sync_group_metadata_from_mls(&self, mls_group_id: String) -> Result<(), MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        self.lock().sync_group_metadata_from_mls(&group_id)?;
        Ok(())
    }

    /// Create a message in a group
    pub fn create_message(
        &self,
        mls_group_id: String,
        sender_public_key: String,
        content: String,
        kind: u16,
    ) -> Result<String, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let sender_pubkey = parse_public_key(&sender_public_key)?;
        let mdk = self.lock();

        let rumor = EventBuilder::new(Kind::Custom(kind), content).build(sender_pubkey);

        let event = mdk.create_message(&group_id, rumor)?;

        let event_json = serde_json::to_string(&event)
            .map_err(|e| MdkUniffiError::InvalidInput(format!("Failed to serialize event: {e}")))?;

        Ok(event_json)
    }

    /// Update the current member's leaf node in an MLS group
    pub fn self_update(&self, mls_group_id: String) -> Result<AddMembersResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let mdk = self.lock();
        let result = mdk.self_update(&group_id)?;

        let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
            MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
        })?;

        let welcome_rumors_json: Option<Vec<String>> = result
            .welcome_rumors
            .map(|rumors| {
                rumors
                    .iter()
                    .map(|rumor| {
                        serde_json::to_string(rumor).map_err(|e| {
                            MdkUniffiError::InvalidInput(format!(
                                "Failed to serialize welcome rumor: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(AddMembersResult {
            evolution_event_json,
            welcome_rumors_json,
            mls_group_id: hex::encode(result.mls_group_id.as_slice()),
        })
    }

    /// Create a proposal to leave the group
    pub fn leave_group(&self, mls_group_id: String) -> Result<AddMembersResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;
        let mdk = self.lock();
        let result = mdk.leave_group(&group_id)?;

        let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
            MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
        })?;

        let welcome_rumors_json: Option<Vec<String>> = result
            .welcome_rumors
            .map(|rumors| {
                rumors
                    .iter()
                    .map(|rumor| {
                        serde_json::to_string(rumor).map_err(|e| {
                            MdkUniffiError::InvalidInput(format!(
                                "Failed to serialize welcome rumor: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(AddMembersResult {
            evolution_event_json,
            welcome_rumors_json,
            mls_group_id: hex::encode(result.mls_group_id.as_slice()),
        })
    }

    /// Update group data (name, description, image, relays, admins)
    pub fn update_group_data(
        &self,
        mls_group_id: String,
        update: GroupDataUpdate,
    ) -> Result<AddMembersResult, MdkUniffiError> {
        let group_id = parse_group_id(&mls_group_id)?;

        let mut group_update = NostrGroupDataUpdate::new();

        if let Some(name) = update.name {
            group_update = group_update.name(name);
        }

        if let Some(description) = update.description {
            group_update = group_update.description(description);
        }

        if let Some(image_hash) = update.image_hash {
            group_update = group_update.image_hash(image_hash.and_then(|bytes| {
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            }));
        }

        if let Some(image_key) = update.image_key {
            group_update = group_update.image_key(image_key.and_then(|bytes| {
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            }));
        }

        if let Some(image_nonce) = update.image_nonce {
            group_update = group_update.image_nonce(image_nonce.and_then(|bytes| {
                let mut arr = [0u8; 12];
                if bytes.len() == 12 {
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            }));
        }

        if let Some(relays) = update.relays {
            let relay_urls = parse_relay_urls(&relays)?;
            group_update = group_update.relays(relay_urls);
        }

        if let Some(admins) = update.admins {
            let admin_pubkeys: Result<Vec<PublicKey>, _> =
                admins.iter().map(|a| parse_public_key(a)).collect();
            let admin_pubkeys = admin_pubkeys?;
            group_update = group_update.admins(admin_pubkeys);
        }

        let mdk = self.lock();
        let result = mdk.update_group_data(&group_id, group_update)?;

        let evolution_event_json = serde_json::to_string(&result.evolution_event).map_err(|e| {
            MdkUniffiError::InvalidInput(format!("Failed to serialize evolution event: {e}"))
        })?;

        let welcome_rumors_json: Option<Vec<String>> = result
            .welcome_rumors
            .map(|rumors| {
                rumors
                    .iter()
                    .map(|rumor| {
                        serde_json::to_string(rumor).map_err(|e| {
                            MdkUniffiError::InvalidInput(format!(
                                "Failed to serialize welcome rumor: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(AddMembersResult {
            evolution_event_json,
            welcome_rumors_json,
            mls_group_id: hex::encode(result.mls_group_id.as_slice()),
        })
    }

    /// Process an incoming MLS message
    pub fn process_message(
        &self,
        event_json: String,
    ) -> Result<ProcessMessageResult, MdkUniffiError> {
        let event: Event = parse_json(&event_json, "event JSON")?;
        let mdk = self.lock();
        let result = mdk.process_message(&event)?;

        Ok(match result {
            MessageProcessingResult::ApplicationMessage(message) => {
                ProcessMessageResult::ApplicationMessage {
                    message: Message::from(message),
                }
            }
            MessageProcessingResult::Proposal(update_result) => {
                let evolution_event_json = serde_json::to_string(&update_result.evolution_event)
                    .map_err(|e| {
                        MdkUniffiError::InvalidInput(format!(
                            "Failed to serialize evolution event: {e}"
                        ))
                    })?;

                let welcome_rumors_json: Option<Vec<String>> = update_result
                    .welcome_rumors
                    .map(|rumors| {
                        rumors
                            .iter()
                            .map(|rumor| {
                                serde_json::to_string(rumor).map_err(|e| {
                                    MdkUniffiError::InvalidInput(format!(
                                        "Failed to serialize welcome rumor: {e}"
                                    ))
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?;

                ProcessMessageResult::Proposal {
                    result: AddMembersResult {
                        evolution_event_json,
                        welcome_rumors_json,
                        mls_group_id: hex::encode(update_result.mls_group_id.as_slice()),
                    },
                }
            }
            MessageProcessingResult::ExternalJoinProposal { mls_group_id } => {
                ProcessMessageResult::ExternalJoinProposal {
                    mls_group_id: hex::encode(mls_group_id.as_slice()),
                }
            }
            MessageProcessingResult::Commit { mls_group_id } => ProcessMessageResult::Commit {
                mls_group_id: hex::encode(mls_group_id.as_slice()),
            },
            MessageProcessingResult::Unprocessable { mls_group_id } => {
                ProcessMessageResult::Unprocessable {
                    mls_group_id: hex::encode(mls_group_id.as_slice()),
                }
            }
        })
    }
}

/// Result of creating a key package
#[derive(uniffi::Record)]
pub struct KeyPackageResult {
    /// Hex-encoded key package
    pub key_package: String,
    /// JSON-encoded tags for the key package event
    pub tags: Vec<Vec<String>>,
}

/// Result of creating a group
#[derive(uniffi::Record)]
pub struct CreateGroupResult {
    /// The created group
    pub group: Group,
    /// JSON-encoded welcome rumors to be published
    pub welcome_rumors_json: Vec<String>,
}

/// Result of adding members to a group
#[derive(uniffi::Record)]
pub struct AddMembersResult {
    /// JSON-encoded evolution event to be published
    pub evolution_event_json: String,
    /// Optional JSON-encoded welcome rumors to be published
    pub welcome_rumors_json: Option<Vec<String>>,
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
}

/// Configuration for updating group data with optional fields
#[derive(uniffi::Record)]
pub struct GroupDataUpdate {
    /// Group name (optional)
    pub name: Option<String>,
    /// Group description (optional)
    pub description: Option<String>,
    /// Group image hash (optional, use Some(None) to clear)
    pub image_hash: Option<Option<Vec<u8>>>,
    /// Group image encryption key (optional, use Some(None) to clear)
    pub image_key: Option<Option<Vec<u8>>>,
    /// Group image encryption nonce (optional, use Some(None) to clear)
    pub image_nonce: Option<Option<Vec<u8>>>,
    /// Relays used by the group (optional)
    pub relays: Option<Vec<String>>,
    /// Group admins (optional)
    pub admins: Option<Vec<String>>,
}

/// Result of processing a message
#[derive(uniffi::Enum)]
pub enum ProcessMessageResult {
    /// An application message (usually a chat message)
    ApplicationMessage {
        /// The processed message
        message: Message,
    },
    /// A proposal message (add/remove member proposal)
    Proposal {
        /// The proposal result containing evolution event and welcome rumors
        result: AddMembersResult,
    },
    /// External join proposal
    ExternalJoinProposal {
        /// Hex-encoded MLS group ID this proposal belongs to
        mls_group_id: String,
    },
    /// Commit message
    Commit {
        /// Hex-encoded MLS group ID this commit applies to
        mls_group_id: String,
    },
    /// Unprocessable message
    Unprocessable {
        /// Hex-encoded MLS group ID of the message that could not be processed
        mls_group_id: String,
    },
}

/// Group representation
#[derive(uniffi::Record)]
pub struct Group {
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
    /// Hex-encoded Nostr group ID
    pub nostr_group_id: String,
    /// Group name
    pub name: String,
    /// Group description
    pub description: String,
    /// Optional group image hash
    pub image_hash: Option<Vec<u8>>,
    /// Optional group image encryption key
    pub image_key: Option<Vec<u8>>,
    /// Optional group image encryption nonce
    pub image_nonce: Option<Vec<u8>>,
    /// List of admin public keys (hex-encoded)
    pub admin_pubkeys: Vec<String>,
    /// Last message event ID (hex-encoded)
    pub last_message_id: Option<String>,
    /// Timestamp of last message (Unix timestamp)
    pub last_message_at: Option<u64>,
    /// Current epoch number
    pub epoch: u64,
    /// Group state (e.g., "active", "archived")
    pub state: String,
}

impl From<group_types::Group> for Group {
    fn from(g: group_types::Group) -> Self {
        Self {
            mls_group_id: hex::encode(g.mls_group_id.as_slice()),
            nostr_group_id: hex::encode(g.nostr_group_id),
            name: g.name,
            description: g.description,
            image_hash: g.image_hash.map(Into::into),
            image_key: g.image_key.map(Into::into),
            image_nonce: g.image_nonce.map(Into::into),
            admin_pubkeys: g.admin_pubkeys.into_iter().map(|pk| pk.to_hex()).collect(),
            last_message_id: g.last_message_id.map(|id| id.to_hex()),
            last_message_at: g.last_message_at.map(|ts| ts.as_u64()),
            epoch: g.epoch,
            state: g.state.as_str().to_string(),
        }
    }
}

/// Message representation
#[derive(uniffi::Record)]
pub struct Message {
    /// Message ID (hex-encoded event ID)
    pub id: String,
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
    /// Hex-encoded Nostr group ID
    pub nostr_group_id: String,
    /// Event ID (hex-encoded)
    pub event_id: String,
    /// Sender public key (hex-encoded)
    pub sender_pubkey: String,
    /// JSON representation of the event
    pub event_json: String,
    /// Timestamp when message was processed (Unix timestamp)
    pub processed_at: u64,
    /// Message kind
    pub kind: u16,
    /// Message state (e.g., "processed", "pending")
    pub state: String,
}

impl From<message_types::Message> for Message {
    fn from(m: message_types::Message) -> Self {
        let nostr_group_id = m
            .event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::h())
            .and_then(|t| t.content())
            .unwrap_or_default()
            .to_string();

        let event_json = serde_json::to_string(&m.event).unwrap_or_else(|_| "{}".to_string());

        Self {
            id: m.id.to_hex(),
            mls_group_id: hex::encode(m.mls_group_id.as_slice()),
            nostr_group_id,
            event_id: m.wrapper_event_id.to_hex(),
            sender_pubkey: m.pubkey.to_hex(),
            event_json,
            processed_at: m.created_at.as_u64(),
            kind: m.kind.as_u16(),
            state: m.state.as_str().to_string(),
        }
    }
}

/// Welcome representation
#[derive(uniffi::Record)]
pub struct Welcome {
    /// Welcome ID (hex-encoded event ID)
    pub id: String,
    /// JSON representation of the welcome event
    pub event_json: String,
    /// Hex-encoded MLS group ID
    pub mls_group_id: String,
    /// Hex-encoded Nostr group ID
    pub nostr_group_id: String,
    /// Group name
    pub group_name: String,
    /// Group description
    pub group_description: String,
    /// Optional group image hash
    pub group_image_hash: Option<Vec<u8>>,
    /// Optional group image encryption key
    pub group_image_key: Option<Vec<u8>>,
    /// Optional group image encryption nonce
    pub group_image_nonce: Option<Vec<u8>>,
    /// List of admin public keys (hex-encoded)
    pub group_admin_pubkeys: Vec<String>,
    /// List of relay URLs for the group
    pub group_relays: Vec<String>,
    /// Welcomer public key (hex-encoded)
    pub welcomer: String,
    /// Current member count
    pub member_count: u32,
    /// Welcome state (e.g., "pending", "accepted", "declined")
    pub state: String,
    /// Wrapper event ID (hex-encoded)
    pub wrapper_event_id: String,
}

impl From<welcome_types::Welcome> for Welcome {
    fn from(w: welcome_types::Welcome) -> Self {
        let event_json = serde_json::to_string(&w.event).unwrap_or_else(|_| "{}".to_string());

        Self {
            id: w.id.to_hex(),
            event_json,
            mls_group_id: hex::encode(w.mls_group_id.as_slice()),
            nostr_group_id: hex::encode(w.nostr_group_id),
            group_name: w.group_name,
            group_description: w.group_description,
            group_image_hash: w.group_image_hash.map(Into::into),
            group_image_key: w.group_image_key.map(Into::into),
            group_image_nonce: w.group_image_nonce.map(Into::into),
            group_admin_pubkeys: w
                .group_admin_pubkeys
                .into_iter()
                .map(|pk| pk.to_hex())
                .collect(),
            group_relays: w.group_relays.into_iter().map(|r| r.to_string()).collect(),
            welcomer: w.welcomer.to_hex(),
            member_count: w.member_count,
            state: w.state.as_str().to_string(),
            wrapper_event_id: w.wrapper_event_id.to_hex(),
        }
    }
}

/// Prepared group image data ready for upload to Blossom
#[derive(uniffi::Record)]
pub struct GroupImageUpload {
    /// Encrypted image data (ready to upload to Blossom)
    pub encrypted_data: Vec<u8>,
    /// SHA256 hash of encrypted data (verify against Blossom response)
    pub encrypted_hash: Vec<u8>,
    /// Encryption key (store in extension)
    pub image_key: Vec<u8>,
    /// Encryption nonce (store in extension)
    pub image_nonce: Vec<u8>,
    /// Derived keypair secret for Blossom authentication (hex encoded)
    pub upload_secret_key: String,
    /// Original image size before encryption
    pub original_size: u64,
    /// Size after encryption
    pub encrypted_size: u64,
    /// Validated and canonical MIME type
    pub mime_type: String,
    /// Image dimensions (width, height) if available
    pub dimensions: Option<ImageDimensions>,
    /// Blurhash for preview if generated
    pub blurhash: Option<String>,
}

/// Image dimensions
#[derive(uniffi::Record)]
pub struct ImageDimensions {
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

/// Prepare group image for upload
#[uniffi::export]
pub fn prepare_group_image_for_upload(
    image_data: Vec<u8>,
    mime_type: String,
) -> Result<GroupImageUpload, MdkUniffiError> {
    let prepared = core_prepare_group_image_for_upload(&image_data, &mime_type)
        .map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;

    Ok(GroupImageUpload {
        encrypted_data: prepared.encrypted_data,
        encrypted_hash: prepared.encrypted_hash.to_vec(),
        image_key: prepared.image_key.to_vec(),
        image_nonce: prepared.image_nonce.to_vec(),
        upload_secret_key: prepared.upload_keypair.secret_key().to_secret_hex(),
        original_size: prepared.original_size as u64,
        encrypted_size: prepared.encrypted_size as u64,
        mime_type: prepared.mime_type,
        dimensions: prepared.dimensions.map(|(w, h)| ImageDimensions {
            width: w,
            height: h,
        }),
        blurhash: prepared.blurhash,
    })
}

/// Decrypt group image
#[uniffi::export]
pub fn decrypt_group_image(
    encrypted_data: Vec<u8>,
    image_key: Vec<u8>,
    image_nonce: Vec<u8>,
) -> Result<Vec<u8>, MdkUniffiError> {
    let key_arr: [u8; 32] = image_key
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Image key must be 32 bytes".to_string()))?;

    let nonce_arr: [u8; 12] = image_nonce
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Image nonce must be 12 bytes".to_string()))?;

    core_decrypt_group_image(&encrypted_data, &key_arr, &nonce_arr)
        .map_err(|e| MdkUniffiError::Mdk(e.to_string()))
}

/// Derive upload keypair for group image
#[uniffi::export]
pub fn derive_upload_keypair(image_key: Vec<u8>) -> Result<String, MdkUniffiError> {
    let key_arr: [u8; 32] = image_key
        .try_into()
        .map_err(|_| MdkUniffiError::InvalidInput("Image key must be 32 bytes".to_string()))?;

    let keys =
        core_derive_upload_keypair(&key_arr).map_err(|e| MdkUniffiError::Mdk(e.to_string()))?;

    Ok(keys.secret_key().to_secret_hex())
}
