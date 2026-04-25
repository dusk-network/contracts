//! DRC721 event payloads.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::Principal;

/// Transfer event topic.
pub const TRANSFER_TOPIC: &str = "drc721/transfer";
/// Approval event topic.
pub const APPROVAL_TOPIC: &str = "drc721/approval";
/// Approval-for-all event topic.
pub const APPROVAL_FOR_ALL_TOPIC: &str = "drc721/approval_for_all";

/// Transfer event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Transfer {
    /// Sender.
    pub from: Principal,
    /// Recipient.
    pub to: Principal,
    /// Token id.
    pub token_id: u64,
}

/// Approval event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Approval {
    /// Owner.
    pub owner: Principal,
    /// Approved account.
    pub approved: Principal,
    /// Token id.
    pub token_id: u64,
}

/// Approval-for-all event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ApprovalForAll {
    /// Owner.
    pub owner: Principal,
    /// Operator.
    pub operator: Principal,
    /// Approval.
    pub approved: bool,
}
