//! A Rust implementation of the Nostr Message Layer Security (MLS) protocol
//!
//! This crate provides functionality for implementing secure group messaging in Nostr using the MLS protocol.
//! It handles group creation, member management, message encryption/decryption, key management, and storage of groups and messages.
//! The implementation follows the MLS specification while integrating with Nostr's event system.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use mdk_storage_traits::MdkStorageProvider;
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;

mod constant;
#[cfg(feature = "mip04")]
#[cfg_attr(docsrs, doc(cfg(feature = "mip04")))]
pub mod encrypted_media;
pub mod error;
pub mod extension;
pub mod groups;
pub mod key_packages;
pub mod media_processing;
pub mod messages;
pub mod prelude;
#[cfg(test)]
pub mod test_util;
mod util;
pub mod welcomes;

use self::constant::{
    DEFAULT_CIPHERSUITE, GROUP_CONTEXT_REQUIRED_EXTENSIONS, SUPPORTED_EXTENSIONS,
};
pub use self::error::Error;
use self::util::NostrTagFormat;

// Re-export GroupId for convenience
pub use mdk_storage_traits::GroupId;

/// The main struct for the Nostr MLS implementation.
///
/// This struct provides the core functionality for MLS operations in Nostr:
/// - Group management (creation, updates, member management)
/// - Message handling (encryption, decryption, processing)
/// - Key management (key packages, welcome messages)
///
/// It uses a generic storage provider that implements the `MdkStorageProvider` trait,
/// allowing for flexible storage backends.
#[derive(Debug)]
pub struct MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// The MLS ciphersuite used for cryptographic operations
    pub ciphersuite: Ciphersuite,
    /// Required MLS extensions for Nostr functionality
    pub extensions: Vec<ExtensionType>,
    /// The OpenMLS provider implementation for cryptographic and storage operations
    pub provider: MdkProvider<Storage>,
}

/// Provider implementation for OpenMLS that integrates with Nostr.
///
/// This struct implements the OpenMLS Provider trait, providing:
/// - Cryptographic operations through RustCrypto
/// - Storage operations through the generic Storage type
/// - Random number generation through RustCrypto
#[derive(Debug)]
pub struct MdkProvider<Storage>
where
    Storage: MdkStorageProvider,
{
    crypto: RustCrypto,
    storage: Storage,
}

impl<Storage> OpenMlsProvider for MdkProvider<Storage>
where
    Storage: MdkStorageProvider,
{
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage::OpenMlsStorageProvider;

    fn storage(&self) -> &Self::StorageProvider {
        self.storage.openmls_storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Construct new nostr MLS instance
    pub fn new(storage: Storage) -> Self {
        Self {
            ciphersuite: DEFAULT_CIPHERSUITE,
            extensions: SUPPORTED_EXTENSIONS.to_vec(),
            provider: MdkProvider {
                crypto: RustCrypto::default(),
                storage,
            },
        }
    }

    /// Get nostr MLS capabilities
    #[inline]
    pub(crate) fn capabilities(&self) -> Capabilities {
        Capabilities::new(
            None,
            Some(&[self.ciphersuite]),
            Some(&self.extensions),
            None,
            None,
        )
    }

    /// Get nostr mls group's required capabilities extension
    #[inline]
    pub(crate) fn required_capabilities_extension(&self) -> Extension {
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &GROUP_CONTEXT_REQUIRED_EXTENSIONS,
            &[],
            &[],
        ))
    }

    /// Get the ciphersuite value formatted for Nostr tags (hex with 0x prefix)
    pub(crate) fn ciphersuite_value(&self) -> String {
        self.ciphersuite.to_nostr_tag()
    }

    /// Get the extensions value formatted for Nostr tags (array of hex values)
    pub(crate) fn extensions_value(&self) -> Vec<String> {
        self.extensions.iter().map(|e| e.to_nostr_tag()).collect()
    }

    /// Get the storage provider
    pub(crate) fn storage(&self) -> &Storage {
        &self.provider.storage
    }
}

/// Tests module for nostr-mls
#[cfg(test)]
pub mod tests {
    use mdk_memory_storage::MdkMemoryStorage;

    use super::*;

    /// Create a test MDK instance with an in-memory storage provider
    pub fn create_test_mdk() -> MDK<MdkMemoryStorage> {
        MDK::new(MdkMemoryStorage::default())
    }
}
