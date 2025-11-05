//! UniFFI bindings for mdk-core with SQLite storage
//!
//! This crate provides foreign language bindings for mdk-core using UniFFI.
//! It wraps the MDK core functionality with SQLite storage backend.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use mdk_core::{Error as MdkError, MDK};
use mdk_sqlite_storage::MdkSqliteStorage;
use mdk_storage_traits::{
    GroupId, groups::types as group_types, messages::types as message_types,
    welcomes::types as welcome_types,
};
use nostr::{Event, EventId, PublicKey, RelayUrl, TagKind, UnsignedEvent};
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

fn serialize_json<T: serde::Serialize>(value: &T) -> Result<String, MdkUniffiError> {
    serde_json::to_string(value)
        .map_err(|e| MdkUniffiError::InvalidInput(format!("Failed to serialize: {e}")))
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

        let tags: Vec<String> = tags
            .iter()
            .map(|tag| serialize_json(tag))
            .collect::<Result<_, _>>()?;

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
}

/// Result of creating a key package
#[derive(uniffi::Record)]
pub struct KeyPackageResult {
    /// Hex-encoded key package
    pub key_package: String,
    /// JSON-encoded tags for the key package event
    pub tags: Vec<String>,
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
    /// JSON representation of the event
    pub event_json: String,
    /// Timestamp when message was processed (Unix timestamp)
    pub processed_at: u64,
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
            event_json,
            processed_at: m.created_at.as_u64(),
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
