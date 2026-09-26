// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Dusk principal identity.

use alloc::vec::Vec;
use core::cmp::Ordering;

use bytecheck::CheckBytes;
#[cfg(feature = "serde")]
use dusk_bytes::Serializable;
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::PublicKey as BlsPublicKey;
use dusk_core::signatures::schnorr::PublicKey as SchnorrPublicKey;
use dusk_core::JubJubAffine;
use rkyv::{Archive, Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::de::Error as _;

/// Raw byte length of a Dusk Moonlight BLS public key.
pub const BLS_PUBLIC_KEY_BYTES: usize = 193;

/// Coarse principal kind for policy decisions and event indexing.
#[derive(
    Archive,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub enum PrincipalKind {
    /// Transparent Moonlight public account.
    Moonlight,
    /// Privacy-preserving Phoenix authorization identity.
    Phoenix,
    /// Dusk contract id.
    Contract,
}

/// An actor that can own assets, hold roles, or authorize contract actions.
///
/// Phoenix identity is represented as compressed Schnorr public-key bytes. The
/// primitive deliberately does not pretend that a Phoenix transaction exposes
/// an Ethereum-like caller address.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[archive_attr(derive(CheckBytes))]
pub enum Principal {
    /// Transparent Moonlight public account, stored as raw BLS public-key
    /// bytes.
    Moonlight([u8; BLS_PUBLIC_KEY_BYTES]),
    /// Phoenix Schnorr authorization identity.
    Phoenix([u8; 32]),
    /// Contract account.
    Contract(ContractId),
}

impl Principal {
    /// Returns the principal kind.
    pub const fn kind(&self) -> PrincipalKind {
        match self {
            Self::Moonlight(_) => PrincipalKind::Moonlight,
            Self::Phoenix(_) => PrincipalKind::Phoenix,
            Self::Contract(_) => PrincipalKind::Contract,
        }
    }

    /// Constructs a Moonlight principal from a public key.
    pub fn moonlight(pk: &BlsPublicKey) -> Self {
        Self::Moonlight(pk.to_raw_bytes())
    }

    /// Constructs a contract principal from a contract id.
    pub const fn contract(id: ContractId) -> Self {
        Self::Contract(id)
    }

    /// Constructs a Phoenix principal from raw compressed public-key bytes.
    pub const fn phoenix(public_key_bytes: [u8; 32]) -> Self {
        Self::Phoenix(public_key_bytes)
    }

    /// Constructs a Phoenix principal from a Schnorr public key.
    pub fn phoenix_public_key(pk: &SchnorrPublicKey) -> Self {
        Self::Phoenix(JubJubAffine::from(pk.as_ref()).to_bytes())
    }

    /// Returns true when this is the reserved all-zero principal value.
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Moonlight(bytes) => bytes.iter().all(|byte| *byte == 0),
            Self::Phoenix(bytes) => bytes.iter().all(|byte| *byte == 0),
            Self::Contract(id) => id.to_bytes().iter().all(|byte| *byte == 0),
        }
    }

    /// Stable byte representation used for hashing and replay keys.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(match self {
            Self::Moonlight(_) => 0,
            Self::Phoenix(_) => 1,
            Self::Contract(_) => 2,
        });
        match self {
            Self::Moonlight(bytes) => out.extend_from_slice(bytes),
            Self::Phoenix(bytes) => out.extend_from_slice(bytes),
            Self::Contract(id) => out.extend_from_slice(&id.to_bytes()),
        }
        out
    }
}

impl From<BlsPublicKey> for Principal {
    fn from(value: BlsPublicKey) -> Self {
        Self::moonlight(&value)
    }
}

impl From<ContractId> for Principal {
    fn from(value: ContractId) -> Self {
        Self::Contract(value)
    }
}

impl PartialOrd for Principal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Principal {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Moonlight(lhs), Self::Moonlight(rhs)) => lhs.cmp(rhs),
            (Self::Phoenix(lhs), Self::Phoenix(rhs)) => lhs.cmp(rhs),
            (Self::Contract(lhs), Self::Contract(rhs)) => lhs.cmp(rhs),
            _ => self.kind().cmp(&other.kind()),
        }
    }
}

/// JSON writes a principal in the form dusk-core uses for the same key or id:
///
/// ```text
/// {"Moonlight": "<base58 BLS public key>"}
/// {"Phoenix": "<base58 Schnorr public key>"}
/// {"Contract": "<hex contract id>"}
/// ```
///
/// The Moonlight form is the address a wallet shows. The Phoenix form is the
/// base58 of the 32-byte Schnorr public key that signs a Phoenix
/// authorization, not a wallet's 64-byte Phoenix address.
///
/// The stored bytes don't change. Reading checks that the key is valid: on the
/// curve, in the prime-order subgroup and not the identity. Writing gives an
/// address only when the stored bytes are exactly those of a valid key, so a
/// JSON address always maps to exactly the stored principal.
///
/// A contract doesn't check the principals in its call arguments, so stored
/// bytes need not be a valid key. Writing never fails: such bytes are written
/// as hex under a key of their own, which reading rejects:
///
/// ```text
/// {"InvalidMoonlight": "<hex of the 193 stored bytes>"}
/// {"InvalidPhoenix": "<hex of the 32 stored bytes>"}
/// ```
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
enum Address {
    Moonlight(BlsPublicKey),
    Phoenix(SchnorrPublicKey),
    Contract(ContractId),
    #[serde(skip_deserializing, serialize_with = "hex::serde::serialize")]
    InvalidMoonlight([u8; BLS_PUBLIC_KEY_BYTES]),
    #[serde(skip_deserializing, serialize_with = "hex::serde::serialize")]
    InvalidPhoenix([u8; 32]),
}

#[cfg(feature = "serde")]
impl Address {
    /// Returns the address of a stored principal, or its invalid form when
    /// the stored bytes aren't exactly those of a valid key.
    fn of(principal: &Principal) -> Self {
        match *principal {
            Principal::Moonlight(bytes) => Self::moonlight_key(&bytes)
                .map_or(Self::InvalidMoonlight(bytes), Self::Moonlight),
            Principal::Phoenix(bytes) => Self::phoenix_key(&bytes)
                .map_or(Self::InvalidPhoenix(bytes), Self::Phoenix),
            Principal::Contract(id) => Self::Contract(id),
        }
    }

    /// Returns the valid key whose raw form is exactly `bytes`.
    fn moonlight_key(
        bytes: &[u8; BLS_PUBLIC_KEY_BYTES],
    ) -> Option<BlsPublicKey> {
        // The last byte is the infinity flag, which must be 0 or 1.
        if bytes[BLS_PUBLIC_KEY_BYTES - 1] > 1 {
            return None;
        }
        // SAFETY: `from_slice_unchecked` only copies the bytes into a point
        // without checking it. The point is used only to get its compressed
        // form, which `from_bytes` then checks.
        let unchecked = unsafe { BlsPublicKey::from_slice_unchecked(bytes) };
        let pk = BlsPublicKey::from_bytes(&unchecked.to_bytes()).ok()?;
        (pk.is_valid() && pk.to_raw_bytes() == *bytes).then_some(pk)
    }

    /// Returns the valid key whose compressed form is exactly `bytes`.
    fn phoenix_key(bytes: &[u8; 32]) -> Option<SchnorrPublicKey> {
        let pk = SchnorrPublicKey::from_bytes(bytes).ok()?;
        (pk.is_valid() && pk.to_bytes() == *bytes).then_some(pk)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Principal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&Address::of(self), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Principal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match <Address as serde::Deserialize>::deserialize(deserializer)? {
            Address::Moonlight(pk) if pk.is_valid() => Ok(Self::moonlight(&pk)),
            Address::Phoenix(pk) if pk.is_valid() => {
                Ok(Self::phoenix_public_key(&pk))
            }
            Address::Contract(id) => Ok(Self::contract(id)),
            // Reading never gives the invalid forms: they skip deserializing.
            Address::Moonlight(_) | Address::InvalidMoonlight(_) => {
                Err(D::Error::custom("invalid Moonlight public key"))
            }
            Address::Phoenix(_) | Address::InvalidPhoenix(_) => {
                Err(D::Error::custom("invalid Phoenix public key"))
            }
        }
    }
}
