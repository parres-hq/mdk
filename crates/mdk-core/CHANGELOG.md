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
