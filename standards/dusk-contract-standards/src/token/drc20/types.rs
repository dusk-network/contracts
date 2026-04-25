//! DRC20 rkyv-compatible call types.

use alloc::string::String;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::auth::SignedAuthorization;
use crate::core::Principal;

/// One initial balance entry.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct InitBalance {
    /// Recipient.
    pub account: Principal,
    /// Amount.
    pub amount: u64,
}

/// Initialization input.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    /// Name.
    pub name: String,
    /// Symbol.
    pub symbol: String,
    /// Decimals.
    pub decimals: u8,
    /// Initial balances.
    pub initial_balances: Vec<InitBalance>,
}

/// Balance query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct BalanceOf {
    /// Account.
    pub account: Principal,
}

/// Allowance query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Allowance {
    /// Owner.
    pub owner: Principal,
    /// Spender.
    pub spender: Principal,
}

/// Transfer call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TransferCall {
    /// Recipient.
    pub to: Principal,
    /// Amount.
    pub amount: u64,
}

/// Approve call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ApproveCall {
    /// Spender.
    pub spender: Principal,
    /// Amount.
    pub amount: u64,
}

/// Increase allowance call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct IncreaseAllowanceCall {
    /// Spender.
    pub spender: Principal,
    /// Added amount.
    pub added_amount: u64,
}

/// Decrease allowance call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct DecreaseAllowanceCall {
    /// Spender.
    pub spender: Principal,
    /// Subtracted amount.
    pub subtracted_amount: u64,
}

/// Transfer from call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TransferFromCall {
    /// Owner.
    pub owner: Principal,
    /// Recipient.
    pub to: Principal,
    /// Amount.
    pub amount: u64,
}

/// Signed approval call for Moonlight/Phoenix owner authorization.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SignedApproveCall {
    /// Allowance owner. Must match the signed action principal.
    pub owner: Principal,
    /// Spender.
    pub spender: Principal,
    /// Allowance amount.
    pub amount: u64,
    /// Replay-protected authorization for this approval payload.
    pub authorization: SignedAuthorization,
}
