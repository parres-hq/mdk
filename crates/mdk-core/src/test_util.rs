//! Test utilities for the nostr-mls crate
//!
//! This module provides shared test utilities used across multiple test modules
//! to avoid code duplication and ensure consistency in test setup.

use crate::GroupId;
use mdk_storage_traits::MdkStorageProvider;
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, RelayUrl};

use crate::MDK;
use crate::groups::NostrGroupConfigData;

/// Creates test group members with standard configuration
///
/// Returns a tuple of (creator_keys, member_keys_vec, admin_pubkeys_vec)
/// where the creator and first member are admins.
pub fn create_test_group_members() -> (Keys, Vec<Keys>, Vec<PublicKey>) {
    let creator = Keys::generate();
    let member1 = Keys::generate();
    let member2 = Keys::generate();

    let creator_pk = creator.public_key();
    let members = vec![member1, member2];
    let admins = vec![creator_pk, members[0].public_key()];

    (creator, members, admins)
}

/// Creates a key package event for a member
///
/// This helper creates a properly signed key package event that can be used
/// in group creation or member addition operations.
pub fn create_key_package_event<Storage>(mdk: &MDK<Storage>, member_keys: &Keys) -> Event
where
    Storage: MdkStorageProvider,
{
    let relays = vec![RelayUrl::parse("wss://test.relay").unwrap()];
    let (key_package_hex, tags) = mdk
        .create_key_package_for_event(&member_keys.public_key(), relays)
        .expect("Failed to create key package");

    EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
        .tags(tags.to_vec())
        .sign_with_keys(member_keys)
        .expect("Failed to sign event")
}

/// Creates a key package event with specified public key and signing keys
///
/// This variant allows creating a key package for one public key but signing
/// it with different keys, useful for testing edge cases.
pub fn create_key_package_event_with_key<Storage>(
    mdk: &MDK<Storage>,
    pubkey: &PublicKey,
    signing_keys: &Keys,
) -> Event
where
    Storage: MdkStorageProvider,
{
    let relays = vec![RelayUrl::parse("wss://test.relay").unwrap()];
    let (key_package_hex, tags) = mdk
        .create_key_package_for_event(pubkey, relays)
        .expect("Failed to create key package");

    EventBuilder::new(Kind::MlsKeyPackage, key_package_hex)
        .tags(tags.to_vec())
        .sign_with_keys(signing_keys)
        .expect("Failed to sign event")
}

/// Creates standard test group configuration data
///
/// Returns a NostrGroupConfigData with random test values for creating test groups.
pub fn create_nostr_group_config_data(admins: Vec<PublicKey>) -> NostrGroupConfigData {
    let relays = vec![RelayUrl::parse("wss://test.relay").unwrap()];
    let image_hash = mdk_storage_traits::test_utils::crypto_utils::generate_random_bytes(32)
        .try_into()
        .unwrap();
    let image_key = mdk_storage_traits::test_utils::crypto_utils::generate_random_bytes(32)
        .try_into()
        .unwrap();
    let image_nonce = mdk_storage_traits::test_utils::crypto_utils::generate_random_bytes(12)
        .try_into()
        .unwrap();
    let name = "Test Group".to_owned();
    let description = "A test group for basic testing".to_owned();
    NostrGroupConfigData::new(
        name,
        description,
        Some(image_hash),
        Some(image_key),
        Some(image_nonce),
        relays,
        admins,
    )
}

/// Creates a complete test group and returns the group ID
///
/// This helper function creates a group with the specified creator, members, and admins,
/// then merges the pending commit to complete the group setup.
pub fn create_test_group<Storage>(
    mdk: &MDK<Storage>,
    creator: &Keys,
    members: &[Keys],
    admins: &[PublicKey],
) -> GroupId
where
    Storage: MdkStorageProvider,
{
    let creator_pk = creator.public_key();

    // Create key package events for initial members
    let mut initial_key_package_events = Vec::new();
    for member_keys in members {
        let key_package_event = create_key_package_event(mdk, member_keys);
        initial_key_package_events.push(key_package_event);
    }

    // Create the group
    let create_result = mdk
        .create_group(
            &creator_pk,
            initial_key_package_events,
            create_nostr_group_config_data(admins.to_vec()),
        )
        .expect("Failed to create group");

    let group_id = create_result.group.mls_group_id;

    // Merge the pending commit to apply the member additions
    mdk.merge_pending_commit(&group_id.clone())
        .expect("Failed to merge pending commit");

    group_id
}

/// Creates a test message rumor (unsigned event)
///
/// This helper creates an unsigned event that can be used for testing
/// message creation and processing.
pub fn create_test_rumor(sender_keys: &Keys, content: &str) -> nostr::UnsignedEvent {
    EventBuilder::new(Kind::TextNote, content).build(sender_keys.public_key())
}

/// Helper structure for managing multiple clients in tests
///
/// This structure simplifies testing scenarios involving multiple clients
/// for the same user or multiple users in a group.
pub struct MultiClientTestSetup<Storage>
where
    Storage: MdkStorageProvider,
{
    /// List of clients with their keys and MDK instances
    pub clients: Vec<(Keys, MDK<Storage>)>,
    /// Optional group ID for the test group
    pub group_id: Option<GroupId>,
}

impl<Storage> MultiClientTestSetup<Storage>
where
    Storage: MdkStorageProvider + Default,
{
    /// Create a new multi-client test setup with the specified number of clients
    ///
    /// Each client gets a unique identity (Keys) and MDK instance.
    pub fn new(num_clients: usize) -> Self {
        let mut clients = Vec::new();
        for _ in 0..num_clients {
            let keys = Keys::generate();
            let mdk = MDK::new(Storage::default());
            clients.push((keys, mdk));
        }

        Self {
            clients,
            group_id: None,
        }
    }

    /// Get a reference to a specific client by index
    pub fn get_client(&self, index: usize) -> Option<&(Keys, MDK<Storage>)> {
        self.clients.get(index)
    }

    /// Get a mutable reference to a specific client by index
    pub fn get_client_mut(&mut self, index: usize) -> Option<&mut (Keys, MDK<Storage>)> {
        self.clients.get_mut(index)
    }

    /// Advance the group epoch by creating an update proposal
    ///
    /// This is useful for testing epoch transitions and lookback mechanisms.
    pub fn advance_epoch(&mut self, client_idx: usize) -> Result<(), crate::Error> {
        let group_id = self.group_id.as_ref().ok_or(crate::Error::GroupNotFound)?;

        let client = self
            .get_client(client_idx)
            .ok_or(crate::Error::GroupNotFound)?;
        let mdk = &client.1;

        // Create self-update to advance epoch
        let _update_result = mdk.self_update(group_id)?;
        mdk.merge_pending_commit(group_id)?;

        Ok(())
    }
}

/// Helper for simulating race conditions with controlled timestamps
///
/// This structure helps create deterministic race condition scenarios
/// by allowing control over event timestamps and IDs.
pub struct RaceConditionSimulator {
    /// Base timestamp for generating offset timestamps
    pub base_timestamp: nostr::Timestamp,
}

impl RaceConditionSimulator {
    /// Create a new race condition simulator with the current timestamp
    pub fn new() -> Self {
        Self {
            base_timestamp: nostr::Timestamp::now(),
        }
    }

    /// Create a new simulator with a specific base timestamp
    pub fn with_timestamp(timestamp: nostr::Timestamp) -> Self {
        Self {
            base_timestamp: timestamp,
        }
    }

    /// Get a timestamp offset from the base by the specified number of seconds
    pub fn timestamp_offset(&self, offset_seconds: i64) -> nostr::Timestamp {
        let new_timestamp = (self.base_timestamp.as_u64() as i64 + offset_seconds).max(0) as u64;
        nostr::Timestamp::from(new_timestamp)
    }
}

impl Default for RaceConditionSimulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_helper_function_randomness() {
        let (_, _, admins) = create_test_group_members();

        // Test that the helper works and generates random data
        let config1 = create_nostr_group_config_data(admins.clone());
        let config2 = create_nostr_group_config_data(admins);

        // Both should have the same basic properties
        assert_eq!(config1.name, "Test Group");
        assert_eq!(config2.name, "Test Group");
        assert_eq!(config1.description, "A test group for basic testing");
        assert_eq!(config2.description, "A test group for basic testing");

        // Random helper should return different values (very unlikely to be the same)
        assert_ne!(config1.image_hash, config2.image_hash);
        assert_ne!(config1.image_key, config2.image_key);
        assert_ne!(config1.image_nonce, config2.image_nonce);

        // All should be Some (not None)
        assert!(config1.image_hash.is_some());
        assert!(config1.image_key.is_some());
        assert!(config1.image_nonce.is_some());
        assert!(config2.image_hash.is_some());
        assert!(config2.image_key.is_some());
        assert!(config2.image_nonce.is_some());
    }
}

// ============================================================================
// Test Infrastructure (MockRelay, CorruptionSimulator, TimeController)
// ============================================================================

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Mock relay for simulating relay failures and network conditions
///
/// This structure allows tests to simulate various relay failure scenarios
/// including unavailability, latency, and intermittent failures.
pub struct MockRelay {
    /// Whether the relay is currently available
    available: Arc<AtomicBool>,
    /// Simulated latency in milliseconds
    latency_ms: Arc<AtomicU64>,
    /// Failure rate as a percentage (0-100)
    failure_rate: Arc<AtomicU8>,
    /// Queue of messages sent to this relay
    message_queue: Arc<Mutex<Vec<Event>>>,
    /// Relay URL for identification
    pub url: String,
}

impl MockRelay {
    /// Create a new mock relay with default settings (available, no latency, no failures)
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            available: Arc::new(AtomicBool::new(true)),
            latency_ms: Arc::new(AtomicU64::new(0)),
            failure_rate: Arc::new(AtomicU8::new(0)),
            message_queue: Arc::new(Mutex::new(Vec::new())),
            url: url.into(),
        }
    }

    /// Set whether the relay is available
    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }

    /// Check if the relay is currently available
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }

    /// Set the simulated latency in milliseconds
    pub fn set_latency(&self, ms: u64) {
        self.latency_ms.store(ms, Ordering::SeqCst);
    }

    /// Get the current latency setting
    pub fn get_latency(&self) -> u64 {
        self.latency_ms.load(Ordering::SeqCst)
    }

    /// Set the failure rate as a percentage (0-100)
    pub fn set_failure_rate(&self, rate: u8) {
        let clamped_rate = rate.min(100);
        self.failure_rate.store(clamped_rate, Ordering::SeqCst);
    }

    /// Get the current failure rate
    pub fn get_failure_rate(&self) -> u8 {
        self.failure_rate.load(Ordering::SeqCst)
    }

    /// Simulate sending a message to this relay
    ///
    /// Returns Ok if successful, Err if the relay is unavailable or fails
    pub fn send_message(&self, event: Event) -> Result<(), String> {
        if !self.is_available() {
            return Err(format!("Relay {} is unavailable", self.url));
        }

        // Simulate failure rate
        let failure_rate = self.get_failure_rate();
        if failure_rate > 0 {
            use std::collections::hash_map::RandomState;
            use std::hash::BuildHasher;

            let hash_value = RandomState::new().hash_one(event.id);

            if (hash_value % 100) < failure_rate as u64 {
                return Err(format!("Relay {} simulated failure", self.url));
            }
        }

        // Simulate latency (in real tests, you might want to actually sleep)
        let _latency = self.get_latency();
        // Note: Not actually sleeping here to keep tests fast
        // In real scenarios: std::thread::sleep(Duration::from_millis(latency));

        // Store the message
        self.message_queue.lock().unwrap().push(event);

        Ok(())
    }

    /// Get all messages sent to this relay
    pub fn get_messages(&self) -> Vec<Event> {
        self.message_queue.lock().unwrap().clone()
    }

    /// Clear all messages from the queue
    pub fn clear_messages(&self) {
        self.message_queue.lock().unwrap().clear();
    }

    /// Get the number of messages in the queue
    pub fn message_count(&self) -> usize {
        self.message_queue.lock().unwrap().len()
    }
}

/// Types of corruption that can be simulated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionType {
    /// Flip random bits in the data
    BitFlip,
    /// Truncate the data
    Truncation,
    /// Delete the data entirely
    Deletion,
    /// Replace with invalid data
    InvalidData,
}

/// Targets for corruption simulation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionTarget {
    /// Corrupt group state
    GroupState,
    /// Corrupt epoch secrets
    EpochSecret,
    /// Corrupt message data
    Message,
    /// Corrupt key package data
    KeyPackage,
}

/// Simulator for testing corruption recovery
///
/// This structure helps test how the system handles corrupted data
/// in various storage locations.
pub struct CorruptionSimulator {
    corruption_type: CorruptionType,
    target: CorruptionTarget,
}

impl CorruptionSimulator {
    /// Create a new corruption simulator
    pub fn new(corruption_type: CorruptionType, target: CorruptionTarget) -> Self {
        Self {
            corruption_type,
            target,
        }
    }

    /// Get the corruption type
    pub fn corruption_type(&self) -> CorruptionType {
        self.corruption_type
    }

    /// Get the corruption target
    pub fn target(&self) -> CorruptionTarget {
        self.target
    }

    /// Corrupt a byte array according to the corruption type
    ///
    /// This is a helper method that can be used to corrupt data before
    /// storing it in the test storage implementation.
    pub fn corrupt_data(&self, data: &[u8]) -> Vec<u8> {
        match self.corruption_type {
            CorruptionType::BitFlip => {
                let mut corrupted = data.to_vec();
                if !corrupted.is_empty() {
                    // Flip bits in the first byte
                    corrupted[0] ^= 0xFF;
                }
                corrupted
            }
            CorruptionType::Truncation => {
                let truncate_at = data.len() / 2;
                data[..truncate_at].to_vec()
            }
            CorruptionType::Deletion => Vec::new(),
            CorruptionType::InvalidData => {
                vec![0xFF; data.len()]
            }
        }
    }
}

/// Time controller for deterministic time-based testing
///
/// This structure allows tests to control time progression for testing
/// expiration, timeouts, and other time-dependent behavior.
pub struct TimeController {
    current_time: Arc<Mutex<nostr::Timestamp>>,
}

impl TimeController {
    /// Create a new time controller starting at the current time
    pub fn new() -> Self {
        Self {
            current_time: Arc::new(Mutex::new(nostr::Timestamp::now())),
        }
    }

    /// Create a time controller with a specific starting time
    pub fn with_timestamp(timestamp: nostr::Timestamp) -> Self {
        Self {
            current_time: Arc::new(Mutex::new(timestamp)),
        }
    }

    /// Advance time by the specified duration
    pub fn advance(&self, duration: std::time::Duration) {
        let mut time = self.current_time.lock().unwrap();
        let new_timestamp = time.as_u64() + duration.as_secs();
        *time = nostr::Timestamp::from(new_timestamp);
    }

    /// Set the current time to a specific timestamp
    pub fn set(&self, timestamp: nostr::Timestamp) {
        let mut time = self.current_time.lock().unwrap();
        *time = timestamp;
    }

    /// Get the current time
    pub fn now(&self) -> nostr::Timestamp {
        *self.current_time.lock().unwrap()
    }

    /// Advance time by a number of seconds
    pub fn advance_secs(&self, seconds: u64) {
        self.advance(std::time::Duration::from_secs(seconds));
    }

    /// Advance time by a number of days
    pub fn advance_days(&self, days: u64) {
        self.advance(std::time::Duration::from_secs(days * 24 * 60 * 60));
    }
}

impl Default for TimeController {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create a group and simulate restart
///
/// This function creates a group, then drops the MDK instance and creates
/// a new one with the same storage to simulate an application restart.
pub fn create_group_and_restart<S>(storage: S) -> (MDK<S>, GroupId, Keys, Vec<Keys>)
where
    S: MdkStorageProvider + Clone,
{
    // Create initial MDK and group
    let mdk = MDK::new(storage.clone());
    let (creator, members, admins) = create_test_group_members();
    let group_id = create_test_group(&mdk, &creator, &members, &admins);

    // Drop the MDK to simulate shutdown
    drop(mdk);

    // Create new MDK with same storage (simulating restart)
    let new_mdk = MDK::new(storage);

    (new_mdk, group_id, creator, members)
}

/// Helper to run a test with failing relays
///
/// This function creates a set of mock relays with the specified failure rate
/// and passes them to the test function.
pub fn with_failing_relays<F>(relay_count: usize, failure_rate: u8, test_fn: F)
where
    F: FnOnce(Vec<MockRelay>),
{
    let mut relays = Vec::new();
    for i in 0..relay_count {
        let relay = MockRelay::new(format!("wss://test-relay-{}.com", i));
        relay.set_failure_rate(failure_rate);
        relays.push(relay);
    }

    test_fn(relays);
}

/// Assert that two group states are equal
///
/// This helper provides detailed error messages when group states don't match,
/// making it easier to debug test failures.
pub fn assert_group_state_equal(
    group1: &mdk_storage_traits::groups::types::Group,
    group2: &mdk_storage_traits::groups::types::Group,
    message: &str,
) {
    assert_eq!(
        group1.mls_group_id, group2.mls_group_id,
        "{}: Group IDs don't match",
        message
    );
    assert_eq!(
        group1.nostr_group_id, group2.nostr_group_id,
        "{}: Nostr Group IDs don't match",
        message
    );
    assert_eq!(
        group1.name, group2.name,
        "{}: Group names don't match",
        message
    );
    assert_eq!(
        group1.description, group2.description,
        "{}: Group descriptions don't match",
        message
    );
    assert_eq!(
        group1.epoch, group2.epoch,
        "{}: Epochs don't match",
        message
    );
    assert_eq!(
        group1.admin_pubkeys, group2.admin_pubkeys,
        "{}: Admin lists don't match",
        message
    );
}

/// Helper to simulate network partition
///
/// This function marks a subset of relays as unavailable to simulate
/// a network partition scenario.
pub fn simulate_network_partition(relays: &[MockRelay], unavailable_indices: &[usize]) {
    for (idx, relay) in relays.iter().enumerate() {
        relay.set_available(!unavailable_indices.contains(&idx));
    }
}

#[cfg(test)]
mod infrastructure_tests {
    use super::*;

    #[test]
    fn test_mock_relay_availability() {
        let relay = MockRelay::new("wss://test.relay");

        assert!(relay.is_available(), "Relay should start available");

        relay.set_available(false);
        assert!(!relay.is_available(), "Relay should be unavailable");

        relay.set_available(true);
        assert!(relay.is_available(), "Relay should be available again");
    }

    #[test]
    fn test_mock_relay_latency() {
        let relay = MockRelay::new("wss://test.relay");

        assert_eq!(relay.get_latency(), 0, "Latency should start at 0");

        relay.set_latency(100);
        assert_eq!(relay.get_latency(), 100, "Latency should be 100ms");
    }

    #[test]
    fn test_mock_relay_failure_rate() {
        let relay = MockRelay::new("wss://test.relay");

        assert_eq!(
            relay.get_failure_rate(),
            0,
            "Failure rate should start at 0"
        );

        relay.set_failure_rate(50);
        assert_eq!(relay.get_failure_rate(), 50, "Failure rate should be 50%");

        // Test clamping
        relay.set_failure_rate(150);
        assert_eq!(
            relay.get_failure_rate(),
            100,
            "Failure rate should be clamped to 100%"
        );
    }

    #[test]
    fn test_mock_relay_message_queue() {
        let relay = MockRelay::new("wss://test.relay");
        let keys = Keys::generate();

        assert_eq!(relay.message_count(), 0, "Should start with no messages");

        let event = EventBuilder::new(Kind::TextNote, "test")
            .sign_with_keys(&keys)
            .unwrap();

        relay.send_message(event.clone()).unwrap();
        assert_eq!(relay.message_count(), 1, "Should have 1 message");

        let messages = relay.get_messages();
        assert_eq!(messages.len(), 1, "Should retrieve 1 message");
        assert_eq!(messages[0].id, event.id, "Message IDs should match");

        relay.clear_messages();
        assert_eq!(
            relay.message_count(),
            0,
            "Should have no messages after clear"
        );
    }

    #[test]
    fn test_mock_relay_unavailable_send() {
        let relay = MockRelay::new("wss://test.relay");
        let keys = Keys::generate();

        relay.set_available(false);

        let event = EventBuilder::new(Kind::TextNote, "test")
            .sign_with_keys(&keys)
            .unwrap();

        let result = relay.send_message(event);
        assert!(
            result.is_err(),
            "Send should fail when relay is unavailable"
        );
        assert_eq!(relay.message_count(), 0, "No messages should be queued");
    }

    #[test]
    fn test_corruption_simulator_bit_flip() {
        let simulator =
            CorruptionSimulator::new(CorruptionType::BitFlip, CorruptionTarget::GroupState);
        let data = vec![0x00, 0x11, 0x22];

        let corrupted = simulator.corrupt_data(&data);
        assert_eq!(corrupted.len(), data.len(), "Length should be preserved");
        assert_ne!(corrupted[0], data[0], "First byte should be flipped");
    }

    #[test]
    fn test_corruption_simulator_truncation() {
        let simulator =
            CorruptionSimulator::new(CorruptionType::Truncation, CorruptionTarget::Message);
        let data = vec![0x00; 100];

        let corrupted = simulator.corrupt_data(&data);
        assert_eq!(corrupted.len(), 50, "Data should be truncated to half");
    }

    #[test]
    fn test_corruption_simulator_deletion() {
        let simulator =
            CorruptionSimulator::new(CorruptionType::Deletion, CorruptionTarget::EpochSecret);
        let data = vec![0x00; 100];

        let corrupted = simulator.corrupt_data(&data);
        assert_eq!(corrupted.len(), 0, "Data should be deleted");
    }

    #[test]
    fn test_corruption_simulator_invalid_data() {
        let simulator =
            CorruptionSimulator::new(CorruptionType::InvalidData, CorruptionTarget::KeyPackage);
        let data = vec![0x00; 100];

        let corrupted = simulator.corrupt_data(&data);
        assert_eq!(corrupted.len(), data.len(), "Length should be preserved");
        assert!(
            corrupted.iter().all(|&b| b == 0xFF),
            "All bytes should be 0xFF"
        );
    }

    #[test]
    fn test_time_controller_advance() {
        let controller = TimeController::new();
        let start_time = controller.now();

        controller.advance_secs(3600); // 1 hour
        let after_advance = controller.now();

        assert_eq!(
            after_advance.as_u64() - start_time.as_u64(),
            3600,
            "Time should advance by 1 hour"
        );
    }

    #[test]
    fn test_time_controller_advance_days() {
        let controller = TimeController::new();
        let start_time = controller.now();

        controller.advance_days(7); // 1 week
        let after_advance = controller.now();

        assert_eq!(
            after_advance.as_u64() - start_time.as_u64(),
            7 * 24 * 60 * 60,
            "Time should advance by 1 week"
        );
    }

    #[test]
    fn test_time_controller_set() {
        let controller = TimeController::new();
        let specific_time = nostr::Timestamp::from(1234567890);

        controller.set(specific_time);
        assert_eq!(
            controller.now(),
            specific_time,
            "Time should be set to specific value"
        );
    }

    #[test]
    fn test_simulate_network_partition() {
        let relays = vec![
            MockRelay::new("wss://relay1.com"),
            MockRelay::new("wss://relay2.com"),
            MockRelay::new("wss://relay3.com"),
        ];

        // All should start available
        assert!(relays.iter().all(|r| r.is_available()));

        // Partition: make relay 0 and 2 unavailable
        simulate_network_partition(&relays, &[0, 2]);

        assert!(!relays[0].is_available(), "Relay 0 should be unavailable");
        assert!(relays[1].is_available(), "Relay 1 should be available");
        assert!(!relays[2].is_available(), "Relay 2 should be unavailable");
    }
}
