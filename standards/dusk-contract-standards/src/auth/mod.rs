//! Replay-protected signed authorization helpers.

use alloc::vec::Vec;

use bytecheck::CheckBytes;
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, Signature as BlsSignature,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, Signature as SchnorrSignature,
};
use dusk_core::BlsScalar;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::{
    error, CallContext, NonceDomain, NonceEntry, NonceManager, Principal,
    PrincipalKind, ReplayEntry, ReplayGuard, ReplayKey,
};

/// Stable prefix for authorization messages.
pub const AUTH_MESSAGE_PREFIX: &[u8] = b"dusk-contract-standards/auth/v1";

/// Expected call envelope for an action-bound authorization.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ActionEnvelope {
    /// Contract this authorization is intended for.
    pub contract: ContractId,
    /// Domain-separated nonce stream.
    pub domain: NonceDomain,
    /// Application-level action id.
    pub action_id: [u8; 32],
    /// Hash or commitment of the call payload.
    pub payload_hash: [u8; 32],
}

impl ActionEnvelope {
    /// Creates a new expected action envelope.
    pub const fn new(
        contract: ContractId,
        domain: NonceDomain,
        action_id: [u8; 32],
        payload_hash: [u8; 32],
    ) -> Self {
        Self {
            contract,
            domain,
            action_id,
            payload_hash,
        }
    }
}

/// Contract action authorized by a signature.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct AuthorizedAction {
    /// Contract this authorization is intended for.
    pub contract: ContractId,
    /// Domain-separated nonce stream.
    pub domain: NonceDomain,
    /// Application-level action id.
    pub action_id: [u8; 32],
    /// Expected nonce.
    pub nonce: u64,
    /// Expiration timestamp/height unit selected by the contract.
    ///
    /// A value of zero means no expiry.
    pub expires_at: u64,
    /// Principal being authorized.
    pub principal: Principal,
    /// Hash or commitment of the call payload.
    pub payload_hash: [u8; 32],
}

impl AuthorizedAction {
    /// Returns true when this action has expired at `now`.
    pub const fn is_expired(&self, now: u64) -> bool {
        self.expires_at != 0 && now > self.expires_at
    }

    /// Builds the stable message bytes signed for this action.
    pub fn message_bytes(&self) -> Vec<u8> {
        let principal = self.principal.to_bytes();
        let mut out = Vec::with_capacity(
            AUTH_MESSAGE_PREFIX.len()
                + 32
                + 32
                + 32
                + 8
                + 8
                + 2
                + principal.len()
                + 32,
        );
        out.extend_from_slice(AUTH_MESSAGE_PREFIX);
        out.extend_from_slice(&self.contract.to_bytes());
        out.extend_from_slice(&self.domain);
        out.extend_from_slice(&self.action_id);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(principal.len() as u16).to_be_bytes());
        out.extend_from_slice(&principal);
        out.extend_from_slice(&self.payload_hash);
        out
    }

    /// Hashes the stable message bytes into the scalar signed by Phoenix keys.
    pub fn message_hash(&self) -> BlsScalar {
        hash_message(self.message_bytes())
    }

    /// Panics unless this action matches the expected contract, nonce domain,
    /// action id, and payload hash.
    pub fn assert_matches(
        &self,
        contract: ContractId,
        domain: NonceDomain,
        action_id: [u8; 32],
        payload_hash: [u8; 32],
    ) {
        self.assert_envelope(ActionEnvelope::new(
            contract,
            domain,
            action_id,
            payload_hash,
        ));
    }

    /// Panics unless this action matches the expected call envelope.
    pub fn assert_envelope(&self, envelope: ActionEnvelope) {
        if self.contract != envelope.contract
            || self.domain != envelope.domain
            || self.action_id != envelope.action_id
            || self.payload_hash != envelope.payload_hash
        {
            panic!("{}", error::UNAUTHORIZED);
        }
    }
}

/// Moonlight BLS authorization.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MoonlightAuthorization {
    /// Authorized action.
    pub action: AuthorizedAction,
    /// Moonlight public key.
    pub public_key: BlsPublicKey,
    /// Signature over `action.message_bytes()`.
    pub signature: BlsSignature,
}

/// Phoenix Schnorr authorization.
///
/// This proves control of the Phoenix Schnorr public key represented by
/// `action.principal`. It does not prove ownership or spending of a specific
/// Phoenix note.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PhoenixSignatureAuthorization {
    /// Authorized action.
    pub action: AuthorizedAction,
    /// Phoenix Schnorr public key.
    pub public_key: SchnorrPublicKey,
    /// Signature over `action.message_hash()`.
    pub signature: SchnorrSignature,
    /// Optional extra replay key consumed with the signature.
    pub replay_key: Option<ReplayKey>,
}

/// Explicit signed authorization supplied with a call.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub enum SignedAuthorization {
    /// Moonlight BLS signed action.
    Moonlight(MoonlightAuthorization),
    /// Phoenix Schnorr signed action.
    Phoenix(PhoenixSignatureAuthorization),
}

impl SignedAuthorization {
    /// Returns the action covered by the signature.
    pub const fn action(&self) -> &AuthorizedAction {
        match self {
            Self::Moonlight(auth) => &auth.action,
            Self::Phoenix(auth) => &auth.action,
        }
    }

    /// Panics unless the signed action matches the exact call envelope.
    pub fn assert_action(
        &self,
        contract: ContractId,
        domain: NonceDomain,
        action_id: [u8; 32],
        payload_hash: [u8; 32],
    ) {
        self.assert_envelope(ActionEnvelope::new(
            contract,
            domain,
            action_id,
            payload_hash,
        ));
    }

    /// Panics unless the signed action matches the exact call envelope.
    pub fn assert_envelope(&self, envelope: ActionEnvelope) {
        self.action().assert_envelope(envelope);
    }
}

/// Ergonomic runtime-or-signature authorizer for composing contracts.
///
/// Moonlight and contract principals can pass through the observed call
/// context. Phoenix principals must pass through explicit signed
/// authorization because Phoenix calls do not expose a stable caller identity.
pub struct Authorizer<'a> {
    authorizations: &'a mut AuthorizationManager,
    context: CallContext,
    now: u64,
}

impl<'a> Authorizer<'a> {
    /// Creates a reusable authorizer for one contract call.
    pub fn new(
        authorizations: &'a mut AuthorizationManager,
        context: CallContext,
        now: u64,
    ) -> Self {
        Self {
            authorizations,
            context,
            now,
        }
    }

    /// Returns the observed runtime principal, if any.
    pub const fn observed_principal(&self) -> Option<Principal> {
        self.context.principal
    }

    /// Verifies an exact expected principal.
    pub fn require_principal(
        &mut self,
        expected: Principal,
        authorization: Option<&SignedAuthorization>,
    ) -> Principal {
        self.authorizations.authorize_principal(
            expected,
            self.context,
            authorization,
            self.now,
        )
    }

    /// Verifies an exact expected principal and binds signed fallbacks to a
    /// call envelope before consuming nonce/replay state.
    pub fn require_principal_action(
        &mut self,
        expected: Principal,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> Principal {
        self.authorizations.authorize_principal_action(
            expected,
            self.context,
            authorization,
            envelope,
            self.now,
        )
    }

    /// Verifies a signed authorization and consumes its nonce/replay state.
    ///
    /// This is a low-level primitive. Public contract methods should usually
    /// prefer `require_signed_action` so the intended call envelope is checked
    /// before nonce state is consumed.
    pub fn require_signed(
        &mut self,
        authorization: &SignedAuthorization,
    ) -> Principal {
        self.authorizations
            .authorize_signed(authorization, self.now)
    }

    /// Verifies a signed authorization, applies an authorization predicate,
    /// and only then consumes nonce/replay state.
    pub fn require_signed_if(
        &mut self,
        authorization: &SignedAuthorization,
        is_authorized: impl FnOnce(Principal) -> bool,
    ) -> Principal {
        let principal =
            self.authorizations.verify_signed(authorization, self.now);
        if !is_authorized(principal) {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.authorizations.consume_verified(authorization);
        principal
    }

    /// Verifies a signed authorization for an exact call envelope and consumes
    /// its nonce/replay state.
    pub fn require_signed_action(
        &mut self,
        authorization: &SignedAuthorization,
        envelope: ActionEnvelope,
    ) -> Principal {
        self.authorizations.authorize_signed_action(
            authorization,
            envelope,
            self.now,
        )
    }

    /// Verifies a signed authorization for an exact call envelope, applies an
    /// authorization predicate, and only then consumes nonce/replay state.
    pub fn require_signed_action_if(
        &mut self,
        authorization: &SignedAuthorization,
        envelope: ActionEnvelope,
        is_authorized: impl FnOnce(Principal) -> bool,
    ) -> Principal {
        let principal = self.authorizations.verify_signed_action(
            authorization,
            envelope,
            self.now,
        );
        if !is_authorized(principal) {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.authorizations.consume_verified(authorization);
        principal
    }
}

/// Authorization manager with nonce and replay-key state.
#[derive(Clone, Debug, Default)]
pub struct AuthorizationManager {
    nonces: NonceManager,
    replays: ReplayGuard,
}

impl AuthorizationManager {
    /// Creates an empty manager.
    pub const fn new() -> Self {
        Self {
            nonces: NonceManager::new(),
            replays: ReplayGuard::new(),
        }
    }

    /// Returns current nonce for a principal/domain stream.
    pub fn nonce(&self, principal: Principal, domain: NonceDomain) -> u64 {
        self.nonces.current(principal, domain)
    }

    /// Returns whether a replay key has been consumed.
    pub fn replay_used(&self, principal: Principal, key: ReplayKey) -> bool {
        self.replays.is_used(principal, key)
    }

    /// Authorizes an exact expected principal.
    ///
    /// Moonlight and contract principals can be authorized by the runtime call
    /// context. Moonlight can also be authorized by a BLS signed action.
    /// Phoenix requires a Schnorr signed action because Phoenix does not expose
    /// a stable runtime caller identity to contracts.
    pub fn authorize_principal(
        &mut self,
        expected: Principal,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> Principal {
        match expected.kind() {
            PrincipalKind::Moonlight | PrincipalKind::Contract => {
                if context.principal == Some(expected) {
                    return expected;
                }
            }
            PrincipalKind::Phoenix => {}
        }

        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        let principal = self.verify_signed(authorization, now);
        if principal != expected {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.consume_verified(authorization);
        principal
    }

    /// Authorizes an exact expected principal and binds signed fallbacks to a
    /// call envelope before nonce/replay state is consumed.
    pub fn authorize_principal_action(
        &mut self,
        expected: Principal,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
        now: u64,
    ) -> Principal {
        match expected.kind() {
            PrincipalKind::Moonlight | PrincipalKind::Contract => {
                if context.principal == Some(expected) {
                    return expected;
                }
            }
            PrincipalKind::Phoenix => {}
        }

        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        let principal = self.verify_signed_action(authorization, envelope, now);
        if principal != expected {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.consume_verified(authorization);
        principal
    }

    /// Verifies and consumes a signed authorization, returning its principal.
    ///
    /// This is a low-level primitive. Public contract methods should usually
    /// prefer `authorize_signed_action` so the intended call envelope is
    /// checked before nonce state is consumed.
    pub fn authorize_signed(
        &mut self,
        authorization: &SignedAuthorization,
        now: u64,
    ) -> Principal {
        let principal = self.verify_signed(authorization, now);
        self.consume_verified(authorization);
        principal
    }

    /// Verifies a signed authorization for an exact call envelope and consumes
    /// its nonce/replay state.
    pub fn authorize_signed_action(
        &mut self,
        authorization: &SignedAuthorization,
        envelope: ActionEnvelope,
        now: u64,
    ) -> Principal {
        let principal = self.verify_signed_action(authorization, envelope, now);
        self.consume_verified(authorization);
        principal
    }

    /// Verifies a signed authorization without consuming nonce/replay state.
    fn verify_signed(
        &self,
        authorization: &SignedAuthorization,
        now: u64,
    ) -> Principal {
        match authorization {
            SignedAuthorization::Moonlight(auth) => {
                self.verify_moonlight(auth, now)
            }
            SignedAuthorization::Phoenix(auth) => {
                self.verify_phoenix(auth, now)
            }
        }
    }

    /// Verifies a signed authorization for an exact call envelope without
    /// consuming nonce/replay state.
    fn verify_signed_action(
        &self,
        authorization: &SignedAuthorization,
        envelope: ActionEnvelope,
        now: u64,
    ) -> Principal {
        authorization.assert_envelope(envelope);
        self.verify_signed(authorization, now)
    }

    /// Verifies and consumes a Moonlight BLS authorization.
    pub fn authorize_moonlight(
        &mut self,
        auth: &MoonlightAuthorization,
        now: u64,
    ) -> Principal {
        let principal = self.verify_moonlight(auth, now);
        self.consume_action(principal, auth.action.domain, auth.action.nonce);
        principal
    }

    /// Verifies a Moonlight BLS authorization without consuming nonce state.
    fn verify_moonlight(
        &self,
        auth: &MoonlightAuthorization,
        now: u64,
    ) -> Principal {
        assert_live(&auth.action, now);
        let principal = Principal::moonlight(&auth.public_key);
        if auth.action.principal != principal {
            panic!("{}", error::UNAUTHORIZED);
        }
        let message = auth.action.message_bytes();
        if !verify_bls(&message, &auth.public_key, &auth.signature) {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.assert_nonce(principal, auth.action.domain, auth.action.nonce);
        principal
    }

    /// Verifies and consumes a Phoenix authorization.
    pub fn authorize_phoenix(
        &mut self,
        auth: &PhoenixSignatureAuthorization,
        now: u64,
    ) -> Principal {
        let principal = self.verify_phoenix(auth, now);
        self.consume_action(principal, auth.action.domain, auth.action.nonce);
        if let Some(key) = auth.replay_key {
            self.replays.consume(principal, key);
        }
        principal
    }

    /// Verifies a Phoenix Schnorr authorization without consuming nonce/replay
    /// state.
    fn verify_phoenix(
        &self,
        auth: &PhoenixSignatureAuthorization,
        now: u64,
    ) -> Principal {
        assert_live(&auth.action, now);
        let principal = Principal::phoenix_public_key(&auth.public_key);
        if auth.action.principal != principal {
            panic!("{}", error::UNAUTHORIZED);
        }
        if !verify_schnorr(
            auth.action.message_hash(),
            &auth.public_key,
            &auth.signature,
        ) {
            panic!("{}", error::UNAUTHORIZED);
        }
        if let Some(key) = auth.replay_key {
            if self.replays.is_used(principal, key) {
                panic!("{}", error::REPLAY);
            }
        }
        self.assert_nonce(principal, auth.action.domain, auth.action.nonce);
        principal
    }

    /// Exports nonce streams.
    pub fn nonce_entries(&self) -> Vec<NonceEntry> {
        self.nonces.entries()
    }

    /// Imports nonce streams, keeping the greatest value for duplicates.
    pub fn import_nonce_entries(
        &mut self,
        entries: impl IntoIterator<Item = NonceEntry>,
    ) {
        self.nonces.import_entries(entries);
    }

    /// Exports replay keys.
    pub fn replay_entries(&self) -> Vec<ReplayEntry> {
        self.replays.entries()
    }

    /// Imports replay keys.
    pub fn import_replay_entries(
        &mut self,
        entries: impl IntoIterator<Item = ReplayEntry>,
    ) {
        self.replays.import_entries(entries);
    }

    fn assert_nonce(
        &self,
        principal: Principal,
        domain: NonceDomain,
        expected: u64,
    ) {
        if self.nonces.current(principal, domain) != expected {
            panic!("{}", error::INVALID_NONCE);
        }
    }

    fn consume_verified(&mut self, authorization: &SignedAuthorization) {
        let action = authorization.action();
        self.consume_action(action.principal, action.domain, action.nonce);
        if let SignedAuthorization::Phoenix(auth) = authorization {
            if let Some(key) = auth.replay_key {
                self.replays.consume(action.principal, key);
            }
        }
    }

    fn consume_action(
        &mut self,
        principal: Principal,
        domain: NonceDomain,
        nonce: u64,
    ) {
        self.nonces.consume(principal, domain, nonce);
    }
}

fn assert_live(action: &AuthorizedAction, now: u64) {
    if action.is_expired(now) {
        panic!("Authorization: expired");
    }
}

#[cfg(all(target_family = "wasm", feature = "contract"))]
fn hash_message(message: Vec<u8>) -> BlsScalar {
    dusk_core::abi::hash(message)
}

#[cfg(not(all(target_family = "wasm", feature = "contract")))]
fn hash_message(message: Vec<u8>) -> BlsScalar {
    BlsScalar::hash_to_scalar(&message)
}

#[cfg(all(target_family = "wasm", feature = "contract"))]
fn verify_bls(
    message: &[u8],
    public_key: &BlsPublicKey,
    signature: &BlsSignature,
) -> bool {
    dusk_core::abi::verify_bls(message.to_vec(), *public_key, *signature)
}

#[cfg(not(all(target_family = "wasm", feature = "contract")))]
fn verify_bls(
    message: &[u8],
    public_key: &BlsPublicKey,
    signature: &BlsSignature,
) -> bool {
    public_key.verify(signature, message).is_ok()
}

#[cfg(all(target_family = "wasm", feature = "contract"))]
fn verify_schnorr(
    message: BlsScalar,
    public_key: &SchnorrPublicKey,
    signature: &SchnorrSignature,
) -> bool {
    dusk_core::abi::verify_schnorr(message, *public_key, *signature)
}

#[cfg(not(all(target_family = "wasm", feature = "contract")))]
fn verify_schnorr(
    message: BlsScalar,
    public_key: &SchnorrPublicKey,
    signature: &SchnorrSignature,
) -> bool {
    public_key.verify(signature, message).is_ok()
}
