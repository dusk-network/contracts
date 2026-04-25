//! Access-control and emergency-stop event payloads.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::Principal;

use super::Role;

/// Pause event topic.
pub const PAUSED_TOPIC: &str = "access/paused";
/// Unpause event topic.
pub const UNPAUSED_TOPIC: &str = "access/unpaused";
/// Role-grant event topic.
pub const ROLE_GRANTED_TOPIC: &str = "access/role_granted";
/// Role-revoke event topic.
pub const ROLE_REVOKED_TOPIC: &str = "access/role_revoked";

/// Pause event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Paused {
    /// Principal that authorized the pause.
    pub account: Principal,
}

/// Unpause event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Unpaused {
    /// Principal that authorized the unpause.
    pub account: Principal,
}

/// Role-grant event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoleGranted {
    /// Role id.
    pub role: Role,
    /// Principal receiving the role.
    pub account: Principal,
    /// Principal that authorized the grant.
    pub sender: Principal,
}

/// Role-revoke event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoleRevoked {
    /// Role id.
    pub role: Role,
    /// Principal losing the role.
    pub account: Principal,
    /// Principal that authorized the revoke.
    pub sender: Principal,
}
