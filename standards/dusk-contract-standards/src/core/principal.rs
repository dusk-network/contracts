//! Dusk principal identity.

use alloc::vec::Vec;
use core::cmp::Ordering;

use bytecheck::CheckBytes;
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::PublicKey as BlsPublicKey;
use dusk_core::signatures::schnorr::PublicKey as SchnorrPublicKey;
use dusk_core::JubJubAffine;
use rkyv::{Archive, Deserialize, Serialize};

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

#[cfg(feature = "serde")]
impl serde::Serialize for Principal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Principal", 2)?;
        state.serialize_field("kind", &self.kind())?;
        match self {
            Self::Moonlight(bytes) => {
                state.serialize_field("bytes", &bytes.as_slice())?
            }
            Self::Phoenix(bytes) => {
                state.serialize_field("bytes", &bytes.as_slice())?
            }
            Self::Contract(id) => {
                state.serialize_field("bytes", &id.to_bytes().as_slice())?
            }
        }
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Principal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct PrincipalJson {
            kind: PrincipalKind,
            bytes: Vec<u8>,
        }

        let principal =
            <PrincipalJson as serde::Deserialize>::deserialize(deserializer)?;
        match principal.kind {
            PrincipalKind::Moonlight => {
                let bytes: [u8; BLS_PUBLIC_KEY_BYTES] =
                    principal.bytes.try_into().map_err(|bytes: Vec<u8>| {
                        serde::de::Error::invalid_length(
                            bytes.len(),
                            &"193 Moonlight public-key bytes",
                        )
                    })?;
                Ok(Self::Moonlight(bytes))
            }
            PrincipalKind::Phoenix => {
                let bytes: [u8; 32] =
                    principal.bytes.try_into().map_err(|bytes: Vec<u8>| {
                        serde::de::Error::invalid_length(
                            bytes.len(),
                            &"32 Phoenix public-key bytes",
                        )
                    })?;
                Ok(Self::Phoenix(bytes))
            }
            PrincipalKind::Contract => {
                let bytes: [u8; 32] =
                    principal.bytes.try_into().map_err(|bytes: Vec<u8>| {
                        serde::de::Error::invalid_length(
                            bytes.len(),
                            &"32 contract-id bytes",
                        )
                    })?;
                Ok(Self::Contract(ContractId::from_bytes(bytes)))
            }
        }
    }
}
