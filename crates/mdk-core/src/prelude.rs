//! MDK Public Prelude
//!
//! This module provides the essential types that MDK users need to work with the library.
//! It only includes the core MDK types and storage traits - external dependencies
//! (like `nostr` and `openmls`) should be imported directly by users.
//!
//! ## Usage
//!
//! ```rust
//! use mdk_core::prelude::*;
//! use mdk_memory_storage::MdkMemoryStorage;
//! use nostr::{EventBuilder, Keys, Kind}; // Import nostr types directly
//!
//! let mdk = MDK::new(MdkMemoryStorage::default());
//! ```

// === Core MDK Types ===
/// MDK error type
pub use crate::Error;
/// MDK provider for OpenMLS integration
pub use crate::MdkProvider;
/// The main MDK struct for Nostr MLS operations
pub use crate::MDK;

// === MDK Result Types ===
/// Nostr group data extension
pub use crate::extension::NostrGroupDataExtension;
/// Group operation results
pub use crate::groups::{
    GroupResult, NostrGroupConfigData, NostrGroupDataUpdate, UpdateGroupResult,
};
/// Message processing result variants
pub use crate::messages::MessageProcessingResult;
/// Welcome operation results
pub use crate::welcomes::{JoinedGroupResult, WelcomePreview};

// === Storage Traits (users need these to provide storage implementations) ===
pub use mdk_storage_traits::{Backend, MdkStorageProvider};

// === Storage Type Aliases (convenient for users working with storage) ===
pub use mdk_storage_traits::groups::types as group_types;
pub use mdk_storage_traits::messages::types as message_types;
pub use mdk_storage_traits::welcomes::types as welcome_types;

// === Convenience Result Type ===
/// A [`Result`] alias where the [`Err`] case is [`mdk_core::Error`](crate::Error).
///
/// This is a convenience type that is equivalent to `std::result::Result<T, mdk_core::Error>`.
pub type Result<T> = std::result::Result<T, Error>;
