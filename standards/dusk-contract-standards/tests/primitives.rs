// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::auth::{
    ActionEnvelope, AuthorizationManager, AuthorizedAction, Authorizer,
    MoonlightAuthorization, PhoenixSignatureAuthorization, SignedAuthorization,
    AUTH_MESSAGE_PREFIX,
};
use dusk_contract_standards::core::{
    CallContext, NonceEntry, NonceManager, Principal, ReplayEntry, ReplayGuard,
    BLS_PUBLIC_KEY_BYTES,
};
use dusk_contract_standards::security::ReentrancyGuard;
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::JubJubScalar;
use rand::rngs::StdRng;
use rand::SeedableRng;

const CHAIN_ID: u8 = 0xD5;

fn contract(byte: u8) -> ContractId {
    ContractId::from_bytes([byte; 32])
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
}

fn phoenix_secret(seed: u64) -> SchnorrSecretKey {
    SchnorrSecretKey::from(JubJubScalar::from(seed))
}

fn assert_panics(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}

fn envelope_for(action: AuthorizedAction) -> ActionEnvelope {
    ActionEnvelope::new(
        action.chain_id,
        action.contract,
        action.domain,
        action.action_id,
        action.payload_hash,
    )
}

fn moonlight_action(secret: &BlsSecretKey, nonce: u64) -> AuthorizedAction {
    let public = BlsPublicKey::from(secret);
    AuthorizedAction {
        chain_id: CHAIN_ID,
        contract: contract(1),
        domain: [2u8; 32],
        action_id: [3u8; 32],
        nonce,
        expires_at: 100,
        principal: Principal::moonlight(&public),
        payload_hash: [4u8; 32],
    }
}

fn signed_moonlight(
    secret: &BlsSecretKey,
    action: AuthorizedAction,
) -> SignedAuthorization {
    SignedAuthorization::Moonlight(MoonlightAuthorization {
        action,
        public_key: BlsPublicKey::from(secret),
        signature: secret.sign(&action.message_bytes()),
    })
}

fn phoenix_action(secret: &SchnorrSecretKey, nonce: u64) -> AuthorizedAction {
    let public = SchnorrPublicKey::from(secret);
    AuthorizedAction {
        chain_id: CHAIN_ID,
        contract: contract(11),
        domain: [12u8; 32],
        action_id: [13u8; 32],
        nonce,
        expires_at: 100,
        principal: Principal::phoenix_public_key(&public),
        payload_hash: [14u8; 32],
    }
}

fn signed_phoenix(
    secret: &SchnorrSecretKey,
    action: AuthorizedAction,
    replay_key: Option<[u8; 32]>,
    seed: u64,
) -> SignedAuthorization {
    let public = SchnorrPublicKey::from(secret);
    let mut rng = StdRng::seed_from_u64(seed);
    SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
        action,
        public_key: public,
        signature: secret.sign(&mut rng, action.message_hash()),
        replay_key,
    })
}

#[test]
fn nonce_manager_streams_imports_and_overflow_are_pinned() {
    let principal = Principal::phoenix([1u8; 32]);
    let other = Principal::phoenix([2u8; 32]);
    let domain = [3u8; 32];
    let other_domain = [4u8; 32];
    let mut nonces = NonceManager::new();

    assert_eq!(nonces.current(principal, domain), 0);
    assert_eq!(nonces.consume(principal, domain, 0), 1);
    assert_eq!(nonces.use_next(principal, domain), 1);
    assert_eq!(nonces.current(principal, domain), 2);
    assert_eq!(nonces.current(other, domain), 0);
    assert_eq!(nonces.current(principal, other_domain), 0);

    nonces.invalidate_until(principal, domain, 10);
    assert_eq!(nonces.current(principal, domain), 10);
    assert_panics(|| nonces.invalidate_until(principal, domain, 9));
    assert_eq!(nonces.current(principal, domain), 10);

    nonces.import_entries([
        NonceEntry {
            principal,
            domain,
            nonce: 5,
        },
        NonceEntry {
            principal,
            domain,
            nonce: 12,
        },
        NonceEntry {
            principal: other,
            domain,
            nonce: 7,
        },
    ]);
    assert_eq!(nonces.current(principal, domain), 12);
    assert_eq!(nonces.current(other, domain), 7);

    nonces.invalidate_until(principal, domain, u64::MAX);
    assert_panics(|| {
        nonces.consume(principal, domain, u64::MAX);
    });
    assert_eq!(nonces.current(principal, domain), u64::MAX);
}

#[test]
fn replay_guard_consumes_deduplicates_and_rejects_replay() {
    let principal = Principal::phoenix([5u8; 32]);
    let other = Principal::phoenix([6u8; 32]);
    let key = [7u8; 32];
    let mut replays = ReplayGuard::new();

    assert!(!replays.is_used(principal, key));
    replays.consume(principal, key);
    assert!(replays.is_used(principal, key));
    assert!(!replays.is_used(other, key));
    assert_panics(|| replays.consume(principal, key));

    replays.import_entries([
        ReplayEntry { principal, key },
        ReplayEntry {
            principal: other,
            key,
        },
    ]);
    assert!(replays.is_used(principal, key));
    assert!(replays.is_used(other, key));
}

#[test]
fn principal_bytes_zero_and_ordering_are_stable() {
    let secret = moonlight_secret(21);
    let public = BlsPublicKey::from(&secret);
    let moonlight = Principal::moonlight(&public);
    let phoenix = Principal::phoenix([9u8; 32]);
    let contract_principal = Principal::contract(contract(10));

    assert!(!moonlight.is_zero());
    assert!(Principal::Moonlight([0u8; BLS_PUBLIC_KEY_BYTES]).is_zero());
    assert!(Principal::phoenix([0u8; 32]).is_zero());
    assert!(Principal::contract(ContractId::from_bytes([0u8; 32])).is_zero());

    assert!(moonlight < phoenix);
    assert!(phoenix < contract_principal);

    let moonlight_bytes = moonlight.to_bytes();
    assert_eq!(moonlight_bytes[0], 0);
    assert_eq!(moonlight_bytes.len(), 1 + BLS_PUBLIC_KEY_BYTES);
    assert_eq!(phoenix.to_bytes()[0], 1);
    assert_eq!(phoenix.to_bytes().len(), 33);
    assert_eq!(contract_principal.to_bytes()[0], 2);
    assert_eq!(contract_principal.to_bytes().len(), 33);
}

#[cfg(feature = "serde")]
#[test]
fn principal_serde_roundtrips_all_kinds() {
    let secret = moonlight_secret(22);
    let public = BlsPublicKey::from(&secret);
    let principals = [
        Principal::moonlight(&public),
        Principal::phoenix([23u8; 32]),
        Principal::contract(contract(24)),
    ];

    for principal in principals {
        let json = serde_json::to_string(&principal).unwrap();
        let decoded: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, principal);
    }
}

#[test]
fn authorized_action_message_layout_and_expiry_boundaries_are_stable() {
    let secret = moonlight_secret(31);
    let action = moonlight_action(&secret, 42);
    let principal = action.principal.to_bytes();

    let mut expected = Vec::new();
    expected.extend_from_slice(AUTH_MESSAGE_PREFIX);
    expected.push(action.chain_id);
    expected.extend_from_slice(&action.contract.to_bytes());
    expected.extend_from_slice(&action.domain);
    expected.extend_from_slice(&action.action_id);
    expected.extend_from_slice(&action.nonce.to_be_bytes());
    expected.extend_from_slice(&action.expires_at.to_be_bytes());
    expected.extend_from_slice(&(principal.len() as u16).to_be_bytes());
    expected.extend_from_slice(&principal);
    expected.extend_from_slice(&action.payload_hash);
    assert_eq!(action.message_bytes(), expected);

    let mut no_expiry = action;
    no_expiry.expires_at = 0;
    assert!(!no_expiry.is_expired(u64::MAX));
    assert!(!action.is_expired(100));
    assert!(action.is_expired(101));
}

#[test]
fn moonlight_authorization_covers_envelope_nonce_signature_and_expiry() {
    let secret = moonlight_secret(41);
    let action = moonlight_action(&secret, 0);
    let envelope = envelope_for(action);
    let signed = signed_moonlight(&secret, action);
    let principal = action.principal;
    let mut authorizations = AuthorizationManager::new();

    assert_eq!(
        authorizations.authorize_signed_action(&signed, envelope, 100),
        principal
    );
    assert_eq!(authorizations.nonce(principal, action.domain), 1);
    assert_panics(|| {
        authorizations.authorize_signed_action(&signed, envelope, 100);
    });

    let mismatch_cases = [
        ActionEnvelope::new(
            1,
            action.contract,
            action.domain,
            action.action_id,
            action.payload_hash,
        ),
        ActionEnvelope::new(
            CHAIN_ID,
            contract(42),
            action.domain,
            action.action_id,
            action.payload_hash,
        ),
        ActionEnvelope::new(
            CHAIN_ID,
            action.contract,
            [43u8; 32],
            action.action_id,
            action.payload_hash,
        ),
        ActionEnvelope::new(
            CHAIN_ID,
            action.contract,
            action.domain,
            [44u8; 32],
            action.payload_hash,
        ),
        ActionEnvelope::new(
            CHAIN_ID,
            action.contract,
            action.domain,
            action.action_id,
            [45u8; 32],
        ),
    ];
    for bad_envelope in mismatch_cases {
        let mut manager = AuthorizationManager::new();
        assert_panics(|| {
            manager.authorize_signed_action(&signed, bad_envelope, 100);
        });
        assert_eq!(manager.nonce(principal, action.domain), 0);
    }

    let mut future_nonce = action;
    future_nonce.nonce = 2;
    let future_nonce = signed_moonlight(&secret, future_nonce);
    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        manager.authorize_signed_action(
            &future_nonce,
            envelope_for(action),
            100,
        );
    });
    assert_eq!(manager.nonce(principal, action.domain), 0);

    let mut expired = action;
    expired.expires_at = 99;
    let expired = signed_moonlight(&secret, expired);
    assert_panics(|| {
        AuthorizationManager::new().authorize_signed_action(
            &expired,
            envelope_for(*expired.action()),
            100,
        );
    });

    let other_secret = moonlight_secret(46);
    let bad_signature =
        SignedAuthorization::Moonlight(MoonlightAuthorization {
            action,
            public_key: BlsPublicKey::from(&secret),
            signature: other_secret.sign(&action.message_bytes()),
        });
    assert_panics(|| {
        AuthorizationManager::new().authorize_signed_action(
            &bad_signature,
            envelope,
            100,
        );
    });
}

#[test]
fn phoenix_authorization_covers_envelope_nonce_signature_expiry_and_replay() {
    let secret = phoenix_secret(51);
    let action = phoenix_action(&secret, 0);
    let envelope = envelope_for(action);
    let replay_key = [52u8; 32];
    let signed = signed_phoenix(&secret, action, Some(replay_key), 53);
    let principal = action.principal;
    let mut authorizations = AuthorizationManager::new();

    assert_eq!(
        authorizations.authorize_signed_action(&signed, envelope, 100),
        principal
    );
    assert_eq!(authorizations.nonce(principal, action.domain), 1);
    assert!(authorizations.replay_used(principal, replay_key));
    assert_panics(|| {
        authorizations.authorize_signed_action(&signed, envelope, 100);
    });

    let bad_envelope = ActionEnvelope::new(
        CHAIN_ID,
        action.contract,
        action.domain,
        [54u8; 32],
        action.payload_hash,
    );
    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        manager.authorize_signed_action(&signed, bad_envelope, 100);
    });
    assert_eq!(manager.nonce(principal, action.domain), 0);
    assert!(!manager.replay_used(principal, replay_key));

    let mut future_nonce = action;
    future_nonce.nonce = 1;
    let future_nonce =
        signed_phoenix(&secret, future_nonce, Some(replay_key), 55);
    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        manager.authorize_signed_action(
            &future_nonce,
            envelope_for(action),
            100,
        );
    });
    assert_eq!(manager.nonce(principal, action.domain), 0);
    assert!(!manager.replay_used(principal, replay_key));

    let mut expired = action;
    expired.expires_at = 99;
    let expired = signed_phoenix(&secret, expired, Some(replay_key), 56);
    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        manager.authorize_signed_action(
            &expired,
            envelope_for(*expired.action()),
            100,
        );
    });
    assert_eq!(manager.nonce(principal, action.domain), 0);
    assert!(!manager.replay_used(principal, replay_key));

    let bad_secret = phoenix_secret(57);
    let mut rng = StdRng::seed_from_u64(58);
    let bad_signature =
        SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
            action,
            public_key: SchnorrPublicKey::from(&secret),
            signature: bad_secret.sign(&mut rng, action.message_hash()),
            replay_key: Some(replay_key),
        });
    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        manager.authorize_signed_action(&bad_signature, envelope, 100);
    });
    assert_eq!(manager.nonce(principal, action.domain), 0);
    assert!(!manager.replay_used(principal, replay_key));

    let mut manager = AuthorizationManager::new();
    manager.import_replay_entries([ReplayEntry {
        principal,
        key: replay_key,
    }]);
    assert_panics(|| {
        manager.authorize_signed_action(&signed, envelope, 100);
    });
    assert_eq!(manager.nonce(principal, action.domain), 0);
}

#[test]
fn principal_authorization_consumes_supplied_permit_before_context_fallback() {
    let secret = moonlight_secret(61);
    let action = moonlight_action(&secret, 0);
    let envelope = envelope_for(action);
    let signed = signed_moonlight(&secret, action);
    let principal = action.principal;
    let context = CallContext::from_principal(principal);
    let mut authorizations = AuthorizationManager::new();

    assert_eq!(
        authorizations.authorize_principal_action(
            principal,
            context,
            Some(&signed),
            envelope,
            100,
        ),
        principal
    );
    assert_eq!(authorizations.nonce(principal, action.domain), 1);
    assert_panics(|| {
        authorizations.authorize_principal_action(
            principal,
            context,
            Some(&signed),
            envelope,
            100,
        );
    });

    assert_eq!(
        AuthorizationManager::new().authorize_principal_action(
            principal, context, None, envelope, 100,
        ),
        principal
    );
    assert_panics(|| {
        AuthorizationManager::new().authorize_principal_action(
            principal,
            CallContext::none(),
            None,
            envelope,
            100,
        );
    });

    let mut authorizations = AuthorizationManager::new();
    assert_eq!(
        authorizations.authorize_principal(
            principal,
            context,
            Some(&signed),
            100,
        ),
        principal
    );
    assert_eq!(authorizations.nonce(principal, action.domain), 1);
    assert_panics(|| {
        AuthorizationManager::new().authorize_principal(
            principal,
            CallContext::none(),
            None,
            100,
        );
    });

    let mut expired = action;
    expired.expires_at = 99;
    let expired = signed_moonlight(&secret, expired);
    assert_panics(|| {
        AuthorizationManager::new().authorize_principal_action(
            principal,
            context,
            Some(&expired),
            envelope_for(*expired.action()),
            100,
        );
    });

    let phoenix = Principal::phoenix([62u8; 32]);
    assert_panics(|| {
        AuthorizationManager::new().authorize_principal_action(
            phoenix,
            CallContext::from_principal(phoenix),
            None,
            envelope,
            100,
        );
    });
}

#[test]
fn unbound_authorization_helpers_consume_without_envelope_binding() {
    let secret = moonlight_secret(71);
    let mut action = moonlight_action(&secret, 0);
    let signed = signed_moonlight(&secret, action);
    let principal = action.principal;
    let mut manager = AuthorizationManager::new();

    assert_eq!(manager.authorize_unbound_signed(&signed, 100), principal);
    assert_eq!(manager.nonce(principal, action.domain), 1);

    action.action_id = [72u8; 32];
    let signed = signed_moonlight(&secret, action);
    assert_eq!(
        AuthorizationManager::new().authorize_unbound_signed(&signed, 100),
        principal
    );

    let signed = signed_moonlight(&secret, moonlight_action(&secret, 0));
    let SignedAuthorization::Moonlight(auth) = &signed else {
        unreachable!()
    };
    let mut manager = AuthorizationManager::new();
    assert_eq!(manager.authorize_unbound_moonlight(auth, 100), principal);
    assert_eq!(manager.nonce(principal, auth.action.domain), 1);

    let secret = phoenix_secret(73);
    let action = phoenix_action(&secret, 0);
    let replay_key = [74u8; 32];
    let signed = signed_phoenix(&secret, action, Some(replay_key), 75);
    let SignedAuthorization::Phoenix(auth) = &signed else {
        unreachable!()
    };
    let principal = action.principal;
    let mut manager = AuthorizationManager::new();
    assert_eq!(manager.authorize_unbound_phoenix(auth, 100), principal);
    assert_eq!(manager.nonce(principal, action.domain), 1);
    assert!(manager.replay_used(principal, replay_key));
}

#[test]
fn authorizer_wrapper_routes_context_and_signed_action_paths() {
    let secret = moonlight_secret(81);
    let action = moonlight_action(&secret, 0);
    let envelope = envelope_for(action);
    let signed = signed_moonlight(&secret, action);
    let principal = action.principal;

    let mut manager = AuthorizationManager::new();
    let mut authorizer = Authorizer::new(
        &mut manager,
        CallContext::from_principal(principal),
        100,
    );
    assert_eq!(authorizer.observed_principal(), Some(principal));
    assert_eq!(
        authorizer.require_principal_unbound(principal, None),
        principal
    );
    assert_eq!(
        authorizer.require_principal_action(principal, None, envelope),
        principal
    );
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 0);

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_eq!(
        authorizer.require_signed_action(&signed, envelope),
        principal
    );
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);
}

#[test]
fn authorizer_require_unbound_signed_consumes_valid_authorizations_only() {
    let secret = moonlight_secret(86);
    let action = moonlight_action(&secret, 0);
    let signed = signed_moonlight(&secret, action);
    let principal = action.principal;

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_eq!(authorizer.require_unbound_signed(&signed), principal);
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);

    let bad_secret = moonlight_secret(87);
    let bad_signature =
        SignedAuthorization::Moonlight(MoonlightAuthorization {
            action,
            public_key: BlsPublicKey::from(&secret),
            signature: bad_secret.sign(&action.message_bytes()),
        });
    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_panics(|| {
        authorizer.require_unbound_signed(&bad_signature);
    });
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 0);

    let secret = phoenix_secret(88);
    let action = phoenix_action(&secret, 0);
    let replay_key = [89u8; 32];
    let signed = signed_phoenix(&secret, action, Some(replay_key), 90);
    let principal = action.principal;
    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_eq!(authorizer.require_unbound_signed(&signed), principal);
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);
    assert!(manager.replay_used(principal, replay_key));

    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_panics(|| {
        authorizer.require_unbound_signed(&signed);
    });
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);
    assert!(manager.replay_used(principal, replay_key));
}

#[test]
fn authorizer_if_predicates_consume_only_after_acceptance() {
    let secret = moonlight_secret(91);
    let action = moonlight_action(&secret, 0);
    let envelope = envelope_for(action);
    let signed = signed_moonlight(&secret, action);
    let principal = action.principal;

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_eq!(
        authorizer.require_unbound_signed_if(&signed, |candidate| {
            candidate == principal
        }),
        principal
    );
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_panics(|| {
        authorizer.require_unbound_signed_if(&signed, |_| false);
    });
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 0);

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    let accepts_principal = |candidate| candidate == principal;
    assert_eq!(
        authorizer.require_signed_action_if(
            &signed,
            envelope,
            accepts_principal,
        ),
        principal
    );
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_panics(|| {
        authorizer.require_signed_action_if(&signed, envelope, |_| false);
    });
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 0);
}

#[test]
fn authorizer_if_predicate_rejection_preserves_phoenix_replay_state() {
    let secret = phoenix_secret(101);
    let action = phoenix_action(&secret, 0);
    let envelope = envelope_for(action);
    let replay_key = [102u8; 32];
    let signed = signed_phoenix(&secret, action, Some(replay_key), 103);
    let principal = action.principal;

    let mut manager = AuthorizationManager::new();
    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    assert_panics(|| {
        authorizer.require_signed_action_if(&signed, envelope, |_| false);
    });
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 0);
    assert!(!manager.replay_used(principal, replay_key));

    let mut authorizer =
        Authorizer::new(&mut manager, CallContext::none(), 100);
    let accepts_principal = |candidate| candidate == principal;
    assert_eq!(
        authorizer.require_signed_action_if(
            &signed,
            envelope,
            accepts_principal,
        ),
        principal
    );
    drop(authorizer);
    assert_eq!(manager.nonce(principal, action.domain), 1);
    assert!(manager.replay_used(principal, replay_key));
}

#[test]
fn reentrancy_guard_public_api_resets_after_success_and_panic() {
    let mut guard = ReentrancyGuard::new();
    guard.run(|| {});
    assert!(!guard.entered());

    let result = catch_unwind(AssertUnwindSafe(|| {
        guard.run(|| panic!("boom"));
    }));
    assert!(result.is_err());
    assert!(!guard.entered());
    guard.run(|| {});
}
