//! GroupId wrapper around OpenMLS GroupId

use serde::{Deserialize, Serialize};

/// MDK Group ID wrapper around OpenMLS GroupId
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupId(openmls::group::GroupId);

impl GroupId {
    /// Create a new GroupId from a byte slice
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(openmls::group::GroupId::from_slice(bytes))
    }

    /// Convert the GroupId to a byte slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Convert the GroupId to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Get the underlying OpenMLS GroupId (internal use)
    pub fn inner(&self) -> &openmls::group::GroupId {
        &self.0
    }
}

impl From<openmls::group::GroupId> for GroupId {
    fn from(id: openmls::group::GroupId) -> Self {
        Self(id)
    }
}

impl From<&openmls::group::GroupId> for GroupId {
    fn from(id: &openmls::group::GroupId) -> Self {
        Self(id.clone())
    }
}

impl From<GroupId> for openmls::group::GroupId {
    fn from(id: GroupId) -> Self {
        id.0
    }
}

impl From<&GroupId> for openmls::group::GroupId {
    fn from(id: &GroupId) -> Self {
        id.0.clone()
    }
}
