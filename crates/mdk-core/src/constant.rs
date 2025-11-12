//! Nostr MLS constants

use openmls::extensions::ExtensionType;
use openmls_traits::types::Ciphersuite;

/// Nostr Group Data extension type
pub const NOSTR_GROUP_DATA_EXTENSION_TYPE: u16 = 0xF2EE; // Be FREE

/// Default ciphersuite for Nostr Groups.
/// This is also the only required ciphersuite for Nostr Groups.
pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Extensions that clients advertise support for in their KeyPackage capabilities.
///
/// Per RFC 9420 Section 7.2, this should only include non-default extensions that
/// the client supports. Default extensions (RequiredCapabilities, RatchetTree,
/// ApplicationId, ExternalPub, ExternalSenders) are assumed to be supported by all
/// clients and should NOT be listed here.
///
/// Note: LastResort (0x000a) is included here because OpenMLS requires KeyPackage-level
/// extensions to be declared in capabilities for validation, even though per the MLS
/// Extensions draft it's technically just a KeyPackage marker.
pub const SUPPORTED_EXTENSIONS: [ExtensionType; 2] = [
    ExtensionType::LastResort, // 0x000A - Required by OpenMLS validation
    ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE), // 0xF2EE - NostrGroupData
];

/// Extensions that are required in the GroupContext RequiredCapabilities extension.
///
/// This enforces that all group members must support these extensions. For Marmot,
/// we require the NostrGroupData extension (0xF2EE) to ensure all members can
/// process the Nostr-specific group metadata.
pub const GROUP_CONTEXT_REQUIRED_EXTENSIONS: [ExtensionType; 1] = [
    ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE), // 0xF2EE - NostrGroupData
];

/// Extensions that are advertised in Nostr event tags (mls_extensions tag).
///
/// This MUST match SUPPORTED_EXTENSIONS to accurately advertise what the
/// KeyPackage capabilities contain. This allows other clients to validate
/// compatibility before attempting to add this user to a group.
pub const TAG_EXTENSIONS: [ExtensionType; 2] = [
    ExtensionType::LastResort, // 0x000A - Required in capabilities
    ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE), // 0xF2EE - NostrGroupData
];

// /// GREASE values for MLS.
// TODO: Remove this once we've added GREASE support.
// const GREASE: [u16; 15] = [
//     0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
//     0xBABA, 0xCACA, 0xDADA, 0xEAEA,
// ];
