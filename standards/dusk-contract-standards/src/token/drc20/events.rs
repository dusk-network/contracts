//! DRC20 event payloads.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::Principal;

/// Transfer event topic.
pub const TRANSFER_TOPIC: &str = "drc20/transfer";
/// Approval event topic.
pub const APPROVAL_TOPIC: &str = "drc20/approval";

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
    /// Amount.
    pub amount: u64,
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
    /// Spender.
    pub spender: Principal,
    /// Amount.
    pub amount: u64,
}
