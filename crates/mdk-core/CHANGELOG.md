# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

-->

## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

## [0.5.2] - 2025-10-16

### Breaking changes

- **Message Processing Results**: Enhanced `MessageProcessingResult` and `UpdateGroupResult` to include group context
  - `UpdateGroupResult` now includes `mls_group_id: GroupId` field
  - `MessageProcessingResult` variants `ExternalJoinProposal`, `Commit`, and `Unprocessable` are now struct variants with `mls_group_id: GroupId` field
  - External code pattern matching on these variants must be updated to use struct syntax: `MessageProcessingResult::Commit { .. }` instead of `MessageProcessingResult::Commit`
  - The `Proposal` variant remains unchanged but now contains `UpdateGroupResult` with the new field

### Added

- **Extension Versioning (MIP-01)**: Added version field to `NostrGroupDataExtension`
  - New `version` field (current version: 1) for forward/backward compatibility
  - Constant `NostrGroupDataExtension::CURRENT_VERSION` for version management
  - Automatic migration from legacy format (without version field) to version 1
  - Forward compatibility support for future versions with warnings
  - New `LegacyTlsNostrGroupDataExtension` struct for backward compatibility
  - Comprehensive version field tests including roundtrip, validation, and migration scenarios
- **Comprehensive Event Structure Testing**: Added 17 new compliance tests for MIP-00, MIP-02, and MIP-03
  - 7 tests for Welcome events (MIP-02): structure validation, content validation, KeyPackage references, relay tags, processing flow, and consistency tests
  - 10 tests for Group Message events (MIP-03): structure validation, ephemeral key rotation, commit events, group ID consistency, NIP-44 encryption validation, and complete lifecycle integration tests
  - Tests validate critical security properties (ephemeral keys per message), interoperability (event structure compliance), and prevent regressions
- New error variant `ExtensionFormatError` for extension formatting issues
- New error variant `InvalidExtensionVersion` for unsupported extension versions

### Fixed

- **MIP-00 Compliance**: Fixed key package tag format to match specification
  - `ciphersuite` tag now uses single hex value format: `["ciphersuite", "0x0001"]` instead of string format
  - `mls_extensions` tag now uses multiple hex values: `["mls_extensions", "0x0003", "0x000a", "0x0002", "0xf2ee"]` instead of single comma-separated string
  - Ensures interoperability with other Marmot protocol implementations

### Removed

### Deprecated

## [0.5.1] - 2025-10-01

### Changed

- Update MSRV to 1.90.0 (required by openmls 0.7.1)
- Update openmls to 0.7.1
- Cleanup dependencies (remove unused `rand` crate, make `kamadak-exif` non-optional)

## [0.5.0] - 2025-09-10

**Note**: This is the first release as an independent library. Previously, this code was part of the `rust-nostr` project.

### Breaking changes

- Library split from rust-nostr into independent MDK (Marmot Development Kit) project
- Wrapped `GroupId` from OpenMLS to avoid leaking external types
- Removed aggressive re-exports, use types directly
- Removed public `Result` type
- Smaller prelude focusing on essential exports
- Remove group type from groups (https://github.com/rust-nostr/nostr/commit/1deb718cf0a70c110537b505bdbad881d43d15cf)
- Removed `MDK::update_group_name`, `MDK::update_group_description`, `MDK::update_group_image` in favor of a single method for updating all group data
- Added `admins` member to the `NostrGroupConfigData` (https://github.com/rust-nostr/nostr/pull/1050)
- Changed method signature of `MDK::create_group`. Removed the admins param. Admins are specified in the `NostrGroupConfigData`. (https://github.com/rust-nostr/nostr/pull/1050)

### Changed

- Upgrade openmls to v0.7.0 (https://github.com/rust-nostr/nostr/commit/b0616f4dca544b4076678255062b1133510f2813)

### Added

- **MIP-04 Support**: Full encrypted media support with privacy-focused EXIF handling
  - EXIF metadata sanitization with allowlist-based approach
  - Blurhash generation for image placeholders
  - ChaCha20-Poly1305 AEAD encryption with proper AAD binding
  - SHA-256 file hashing for integrity verification
  - Comprehensive image format support (JPEG, PNG, WebP, GIF)
  - Image dimension validation and metadata extraction
- Group image encryption and management (MIP-01)
- GitHub CI workflow with comprehensive test matrix
- LLM context documentation and development guides
- Improved synchronization between MLSGroup and stored Group state on all commits (https://github.com/rust-nostr/nostr/pull/1050)
- Added `MDK::update_group_data` method to handle updates of any of the fields of the `NostrGroupDataExtension` (https://github.com/rust-nostr/nostr/pull/1050)
- Added Serde support for GroupId

### Fixed

- Bug where group relays weren't being persisted properly on change in NostrGroupDataExtension (https://github.com/rust-nostr/nostr/pull/1056)

## v0.43.0 - 2025/07/28

### Breaking changes

- Changed return type of `MDK::add_members` and `MDK::self_update` (https://github.com/rust-nostr/nostr/pull/934)
- Changed return type of all group and message methods to return Events instead of serialized MLS objects. (https://github.com/rust-nostr/nostr/pull/940)
- Changed the input params of `MDK::create_group`, and additional fields for `NostrGroupDataExtension` (https://github.com/rust-nostr/nostr/pull/965)
- `NostrGroupDataExtension` requires additional `image_nonce` field (https://github.com/rust-nostr/nostr/pull/1054)
- `image_hash` instead of `image_url` (https://github.com/rust-nostr/nostr/pull/1059)

### Added

- Add `MDK::add_members` method for adding members to an existing group (https://github.com/rust-nostr/nostr/pull/931)
- Add `MDK::remove_members` method for removing members from an existing group (https://github.com/rust-nostr/nostr/pull/934)
- Add `MDK::leave_group` method for creating a proposal to leave the group (https://github.com/rust-nostr/nostr/pull/940)
- Add processing of commit messages and basic processing of proposals. (https://github.com/rust-nostr/nostr/pull/940)
- Add `ProcessedMessageState` for processed commits (https://github.com/rust-nostr/nostr/pull/954)
- Add method to check previous exporter_secrets when NIP-44 decrypting kind 445 messages (https://github.com/rust-nostr/nostr/pull/954)
- Add methods to update group name, description and image (https://github.com/rust-nostr/nostr/pull/978)

## v0.42.0 - 2025/05/20

First release (https://github.com/rust-nostr/nostr/pull/843)
