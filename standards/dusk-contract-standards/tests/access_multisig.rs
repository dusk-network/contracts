// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::access::events::{
    Paused, RoleGranted, RoleRevoked, Unpaused,
};
use dusk_contract_standards::access::{
    AccessControl, Ownable, Ownable2Step, OwnerAuthorization, OwnerSet,
    Pausable, Role, RoleAuthorization, DEFAULT_ADMIN_ROLE,
};
use dusk_contract_standards::auth::{
    ActionEnvelope, AuthorizationManager, AuthorizedAction, Authorizer,
    MoonlightAuthorization, PhoenixSignatureAuthorization, SignedAuthorization,
};
use dusk_contract_standards::core::{CallContext, Principal};
use dusk_contract_standards::governance::{
    MultisigAuthorityUpdated, MultisigConfig, MultisigController,
    MultisigControllerConfig, MultisigControllerStatus,
    MultisigOperationCancelled, MultisigOperationConfirmed,
    MultisigOperationExecuted, MultisigOperationProposed, MultisigQuorum,
    MultisigTarget, MultisigTimeLimitsUpdated, ThresholdMultisig,
};
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::transfer::data::ContractCall;
use dusk_core::JubJubScalar;
use rand::rngs::StdRng;
use rand::SeedableRng;

const CHAIN_ID: u8 = 0xD5;
const DOMAIN: [u8; 32] = [41u8; 32];
const ACTION: [u8; 32] = [42u8; 32];
const CONTRACT: [u8; 32] = [43u8; 32];
const PAYLOAD: [u8; 32] = [44u8; 32];

fn assert_panics<R>(f: impl FnOnce() -> R) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}

fn assert_rkyv_roundtrip<T>(value: T)
where
    T: rkyv::Archive
        + rkyv::Serialize<rkyv::ser::serializers::AllocSerializer<1024>>
        + PartialEq
        + core::fmt::Debug,
    T::Archived:
        rkyv::Deserialize<T, rkyv::de::deserializers::SharedDeserializeMap>,
{
    let bytes = rkyv::to_bytes::<_, 1024>(&value).unwrap();
    let decoded = unsafe { rkyv::from_bytes_unchecked::<T>(&bytes) }.unwrap();
    assert_eq!(decoded, value);
}

fn principal(byte: u8) -> Principal {
    Principal::phoenix([byte; 32])
}

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

fn action_for(secret: &BlsSecretKey, nonce: u64) -> AuthorizedAction {
    AuthorizedAction {
        chain_id: CHAIN_ID,
        contract: contract(CONTRACT[0]),
        domain: DOMAIN,
        action_id: ACTION,
        nonce,
        expires_at: 100,
        principal: Principal::moonlight(&BlsPublicKey::from(secret)),
        payload_hash: PAYLOAD,
    }
}

fn envelope() -> ActionEnvelope {
    ActionEnvelope::new(
        CHAIN_ID,
        contract(CONTRACT[0]),
        DOMAIN,
        ACTION,
        PAYLOAD,
    )
}

fn signed(secret: &BlsSecretKey, nonce: u64) -> SignedAuthorization {
    let action = action_for(secret, nonce);
    SignedAuthorization::Moonlight(MoonlightAuthorization {
        action,
        public_key: BlsPublicKey::from(secret),
        signature: secret.sign(&action.message_bytes()),
    })
}

fn phoenix_action_for(
    secret: &SchnorrSecretKey,
    nonce: u64,
) -> AuthorizedAction {
    let public = SchnorrPublicKey::from(secret);
    AuthorizedAction {
        chain_id: CHAIN_ID,
        contract: contract(CONTRACT[0]),
        domain: DOMAIN,
        action_id: ACTION,
        nonce,
        expires_at: 100,
        principal: Principal::phoenix_public_key(&public),
        payload_hash: PAYLOAD,
    }
}

fn signed_phoenix(
    secret: &SchnorrSecretKey,
    nonce: u64,
) -> SignedAuthorization {
    let action = phoenix_action_for(secret, nonce);
    let public = SchnorrPublicKey::from(secret);
    let mut rng = StdRng::seed_from_u64(1000 + nonce);
    SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
        action,
        public_key: public,
        signature: secret.sign(&mut rng, action.message_hash()),
        replay_key: None,
    })
}

fn quorum_for(
    multisig: &ThresholdMultisig,
    context_principal: Principal,
    approvals: &[SignedAuthorization],
) -> MultisigQuorum {
    let authorizations = AuthorizationManager::new();
    multisig.verify_action(
        &authorizations,
        CallContext::from_principal(context_principal),
        approvals,
        envelope(),
        100,
    )
}

fn controller_quorum_for(
    controller: &MultisigController,
    context_principal: Principal,
    approvals: &[SignedAuthorization],
) -> MultisigQuorum {
    let authorizations = AuthorizationManager::new();
    controller.verify_action(
        &authorizations,
        CallContext::from_principal(context_principal),
        approvals,
        envelope(),
        100,
    )
}

fn ownable_auth(ownable: &Ownable, principal: Principal) -> OwnerAuthorization {
    let mut authorizations = AuthorizationManager::new();
    ownable.authorize_owner(
        &mut authorizations,
        CallContext::from_principal(principal),
        None,
        100,
    )
}

fn two_step_auth(
    ownable: &Ownable2Step,
    principal: Principal,
) -> OwnerAuthorization {
    let mut authorizations = AuthorizationManager::new();
    ownable.authorize_owner(
        &mut authorizations,
        CallContext::from_principal(principal),
        None,
        100,
    )
}

fn two_step_pending_auth(
    ownable: &Ownable2Step,
    principal: Principal,
) -> OwnerAuthorization {
    let mut authorizations = AuthorizationManager::new();
    ownable.authorize_pending_owner(
        &mut authorizations,
        CallContext::from_principal(principal),
        None,
        100,
    )
}

fn owner_set_auth(
    owners: &OwnerSet,
    principal: Principal,
) -> OwnerAuthorization {
    let mut authorizations = AuthorizationManager::new();
    owners.authorize_owner(
        &mut authorizations,
        CallContext::from_principal(principal),
        None,
        100,
    )
}

fn role_auth(
    access: &AccessControl,
    role: Role,
    principal: Principal,
) -> RoleAuthorization {
    let mut authorizations = AuthorizationManager::new();
    access.authorize_role(
        role,
        &mut authorizations,
        CallContext::from_principal(principal),
        None,
        100,
    )
}

fn target(byte: u8) -> MultisigTarget {
    MultisigTarget {
        call: ContractCall {
            contract: contract(byte),
            fn_name: "set_value".into(),
            fn_args: vec![byte],
        },
        salt: [byte; 32],
    }
}

#[test]
fn access_and_multisig_events_roundtrip_with_rkyv() {
    let owner = principal(1);
    let next = principal(2);
    let role = [3u8; 32];
    let operation_id = [4u8; 32];

    assert_rkyv_roundtrip(Paused { account: owner });
    assert_rkyv_roundtrip(Unpaused { account: owner });
    assert_rkyv_roundtrip(RoleGranted {
        role,
        account: next,
        sender: owner,
    });
    assert_rkyv_roundtrip(RoleRevoked {
        role,
        account: next,
        sender: owner,
    });
    assert_rkyv_roundtrip(MultisigOperationProposed {
        id: operation_id,
        authorizer: owner,
        confirmations: 1,
        threshold: 2,
        deadline: 100,
    });
    assert_rkyv_roundtrip(MultisigOperationConfirmed {
        id: operation_id,
        authorizer: next,
        confirmations: 2,
        threshold: 2,
        deadline: 100,
    });
    assert_rkyv_roundtrip(MultisigOperationExecuted {
        id: operation_id,
        success: false,
        return_data: vec![],
        error: Some("target reverted".into()),
    });
    assert_rkyv_roundtrip(MultisigOperationCancelled {
        id: operation_id,
        signers: vec![owner, next],
    });
    assert_rkyv_roundtrip(MultisigAuthorityUpdated {
        previous_owners: vec![owner],
        previous_threshold: 1,
        owners: vec![owner, next],
        threshold: 2,
        removed_operations: vec![operation_id],
    });
    assert_rkyv_roundtrip(MultisigTimeLimitsUpdated {
        previous_proposal_ttl: 10,
        previous_tombstone_ttl: 20,
        proposal_ttl: 30,
        tombstone_ttl: 40,
    });

    assert!(
        rkyv::check_archived_root::<MultisigOperationExecuted>(&[0u8]).is_err()
    );
}

#[cfg(feature = "serde")]
#[test]
fn access_and_multisig_events_roundtrip_with_serde_json() {
    let owner = principal(11);
    let next = principal(12);
    let operation_id = [13u8; 32];
    let authority = MultisigAuthorityUpdated {
        previous_owners: vec![owner],
        previous_threshold: 1,
        owners: vec![owner, next],
        threshold: 2,
        removed_operations: vec![operation_id],
    };
    let json = serde_json::to_string(&authority).unwrap();
    let decoded: MultisigAuthorityUpdated =
        serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, authority);

    let executed = MultisigOperationExecuted {
        id: operation_id,
        success: true,
        return_data: vec![1, 2, 3],
        error: None,
    };
    let json = serde_json::to_string(&executed).unwrap();
    let decoded: MultisigOperationExecuted =
        serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, executed);

    let revoked = RoleRevoked {
        role: [14u8; 32],
        account: next,
        sender: owner,
    };
    let json = serde_json::to_string(&revoked).unwrap();
    let decoded: RoleRevoked = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, revoked);
    assert!(serde_json::from_str::<RoleRevoked>(r#"{"role":[]}"#).is_err());
}

#[cfg(feature = "forge")]
#[test]
fn access_and_multisig_event_topics_are_pinned() {
    use dusk_contract_standards::access::events::{
        PAUSED_TOPIC, ROLE_GRANTED_TOPIC, ROLE_REVOKED_TOPIC, UNPAUSED_TOPIC,
    };
    use dusk_contract_standards::governance::{
        MULTISIG_AUTHORITY_UPDATED_TOPIC, MULTISIG_OPERATION_CANCELLED_TOPIC,
        MULTISIG_OPERATION_CONFIRMED_TOPIC, MULTISIG_OPERATION_EXECUTED_TOPIC,
        MULTISIG_OPERATION_PROPOSED_TOPIC, MULTISIG_TIME_LIMITS_UPDATED_TOPIC,
    };
    use dusk_forge::ContractEvent;

    assert_eq!(Paused::TOPICS, &[PAUSED_TOPIC]);
    assert_eq!(Unpaused::TOPICS, &[UNPAUSED_TOPIC]);
    assert_eq!(RoleGranted::TOPICS, &[ROLE_GRANTED_TOPIC]);
    assert_eq!(RoleRevoked::TOPICS, &[ROLE_REVOKED_TOPIC]);
    assert_eq!(
        MultisigOperationProposed::TOPICS,
        &[MULTISIG_OPERATION_PROPOSED_TOPIC]
    );
    assert_eq!(
        MultisigOperationConfirmed::TOPICS,
        &[MULTISIG_OPERATION_CONFIRMED_TOPIC]
    );
    assert_eq!(
        MultisigOperationExecuted::TOPICS,
        &[MULTISIG_OPERATION_EXECUTED_TOPIC]
    );
    assert_eq!(
        MultisigOperationCancelled::TOPICS,
        &[MULTISIG_OPERATION_CANCELLED_TOPIC]
    );
    assert_eq!(
        MultisigAuthorityUpdated::TOPICS,
        &[MULTISIG_AUTHORITY_UPDATED_TOPIC]
    );
    assert_eq!(
        MultisigTimeLimitsUpdated::TOPICS,
        &[MULTISIG_TIME_LIMITS_UPDATED_TOPIC]
    );
}

#[test]
fn ownership_and_role_authorizers_pin_context_and_signed_paths() {
    let moonlight_key = moonlight_secret(201);
    let moonlight = Principal::moonlight(&BlsPublicKey::from(&moonlight_key));
    let phoenix_key = phoenix_secret(202);
    let phoenix =
        Principal::phoenix_public_key(&SchnorrPublicKey::from(&phoenix_key));
    let contract_owner = Principal::contract(contract(203));
    let outsider_key = moonlight_secret(204);
    let outsider = Principal::moonlight(&BlsPublicKey::from(&outsider_key));
    let role = [205u8; 32];

    let mut ownable = Ownable::new();
    ownable.init(moonlight);
    let mut authorizations = AuthorizationManager::new();
    assert_eq!(
        ownable
            .authorize_owner(
                &mut authorizations,
                CallContext::from_principal(moonlight),
                None,
                100,
            )
            .principal(),
        moonlight
    );
    assert_panics(|| {
        ownable.authorize_owner(
            &mut authorizations,
            CallContext::from_principal(outsider),
            None,
            100,
        );
    });

    let mut phoenix_owned = Ownable::new();
    phoenix_owned.init(phoenix);
    assert_panics(|| {
        phoenix_owned.authorize_owner(
            &mut authorizations,
            CallContext::from_principal(phoenix),
            None,
            100,
        );
    });
    let phoenix_signature = signed_phoenix(&phoenix_key, 0);
    assert_eq!(
        phoenix_owned
            .authorize_owner_action(
                &mut authorizations,
                CallContext::none(),
                Some(&phoenix_signature),
                envelope(),
                100,
            )
            .principal(),
        phoenix
    );
    assert_eq!(authorizations.nonce(phoenix, DOMAIN), 1);

    let mut owners = OwnerSet::new();
    owners.init([moonlight, phoenix, contract_owner]);
    assert_eq!(
        owners
            .authorize_owner(
                &mut authorizations,
                CallContext::from_principal(contract_owner),
                None,
                100,
            )
            .principal(),
        contract_owner
    );
    assert_panics(|| {
        owners.authorize_owner(
            &mut authorizations,
            CallContext::from_principal(phoenix),
            None,
            100,
        );
    });
    let phoenix_signature = signed_phoenix(&phoenix_key, 1);
    assert_eq!(
        owners
            .authorize_owner_action(
                &mut authorizations,
                CallContext::none(),
                Some(&phoenix_signature),
                envelope(),
                100,
            )
            .principal(),
        phoenix
    );
    assert_eq!(authorizations.nonce(phoenix, DOMAIN), 2);

    let mut access = AccessControl::new();
    access.init_admin(moonlight);
    let admin_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, moonlight);
    access.grant_role(admin_auth, role, phoenix);
    let admin_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, moonlight);
    access.grant_role(admin_auth, role, contract_owner);
    assert_eq!(
        access
            .authorize_role(
                role,
                &mut authorizations,
                CallContext::from_principal(contract_owner),
                None,
                100,
            )
            .principal(),
        contract_owner
    );
    assert_panics(|| {
        access.authorize_role(
            role,
            &mut authorizations,
            CallContext::from_principal(phoenix),
            None,
            100,
        );
    });
    let phoenix_signature = signed_phoenix(&phoenix_key, 2);
    assert_eq!(
        access
            .authorize_role_action(
                role,
                &mut authorizations,
                CallContext::none(),
                Some(&phoenix_signature),
                envelope(),
                100,
            )
            .principal(),
        phoenix
    );
    assert_eq!(authorizations.nonce(phoenix, DOMAIN), 3);

    let wrong_signature = signed(&outsider_key, 0);
    assert_panics(|| {
        access.authorize_role_action(
            role,
            &mut authorizations,
            CallContext::none(),
            Some(&wrong_signature),
            envelope(),
            100,
        );
    });
    assert_eq!(authorizations.nonce(outsider, DOMAIN), 0);

    let mut authorizer = Authorizer::new(
        &mut authorizations,
        CallContext::from_principal(moonlight),
        100,
    );
    assert_eq!(
        owners
            .authorize_owner_action_with(&mut authorizer, None, envelope())
            .principal(),
        moonlight
    );
}

#[test]
fn ownable_and_owner_set_enforce_owner_transitions() {
    let owner = Principal::contract(contract(1));
    let next = Principal::contract(contract(2));
    let outsider = Principal::contract(contract(3));

    let mut ownable = Ownable::new();
    assert_panics(|| ownable.assert_owner(owner));
    ownable.init(owner);
    assert_eq!(ownable.owner(), Some(owner));
    assert_panics(|| ownable.init(owner));
    assert_panics(|| {
        let outsider_auth = ownable_auth(&ownable, outsider);
        ownable.transfer_ownership(outsider_auth, next);
    });
    let owner_auth = ownable_auth(&ownable, owner);
    assert_panics(|| {
        ownable.transfer_ownership(owner_auth, Principal::phoenix([0; 32]))
    });
    let owner_auth = ownable_auth(&ownable, owner);
    ownable.transfer_ownership(owner_auth, next);
    assert_eq!(ownable.owner(), Some(next));
    let next_auth = ownable_auth(&ownable, next);
    ownable.renounce_ownership(next_auth);
    assert_eq!(ownable.owner(), None);

    let mut two_step = Ownable2Step::new();
    two_step.init(owner);
    let owner_auth = two_step_auth(&two_step, owner);
    two_step.transfer_ownership(owner_auth, next);
    assert_eq!(two_step.pending_owner(), Some(next));
    assert_panics(|| {
        let outsider_auth = two_step_pending_auth(&two_step, outsider);
        two_step.accept_ownership(outsider_auth);
    });
    let next_auth = two_step_pending_auth(&two_step, next);
    two_step.accept_ownership(next_auth);
    assert_eq!(two_step.owner(), Some(next));
    assert_eq!(two_step.pending_owner(), None);

    let mut owners = OwnerSet::new();
    assert_panics(|| owners.init([Principal::phoenix([0; 32])]));
    owners.init([owner, next]);
    assert_eq!(owners.len(), 2);
    assert!(owners.is_owner(owner));
    assert_panics(|| {
        let outsider_auth = owner_set_auth(&owners, outsider);
        owners.remove_owner(outsider_auth, owner);
    });
    let owner_auth = owner_set_auth(&owners, owner);
    owners.replace_owner(owner_auth, next, outsider);
    assert!(!owners.is_owner(next));
    assert!(owners.is_owner(outsider));
    let owner_auth = owner_set_auth(&owners, owner);
    owners.remove_owner(owner_auth, outsider);
    assert_eq!(owners.len(), 1);
    let owner_auth = owner_set_auth(&owners, owner);
    assert_panics(|| owners.remove_owner(owner_auth, owner));
}

#[test]
fn access_control_admin_roles_and_pausable_are_pinned() {
    let admin = Principal::contract(contract(11));
    let member = Principal::contract(contract(12));
    let outsider = Principal::contract(contract(13));
    let role = [14u8; 32];
    let admin_role = [15u8; 32];

    let mut access = AccessControl::new();
    assert_panics(|| access.init_admin(Principal::phoenix([0; 32])));
    access.init_admin(admin);
    assert!(access.has_role(DEFAULT_ADMIN_ROLE, admin));
    assert_panics(|| access.init_admin(admin));

    let mut seeded = AccessControl::new();
    seeded.init_admin_with_roles(admin, [role, admin_role]);
    assert!(seeded.has_role(DEFAULT_ADMIN_ROLE, admin));
    assert!(seeded.has_role(role, admin));
    assert!(seeded.has_role(admin_role, admin));
    assert_panics(|| seeded.init_admin_with_roles(admin, [role]));

    let admin_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, admin);
    access.grant_role(admin_auth, role, member);
    assert!(access.has_role(role, member));
    assert_panics(|| {
        let outsider_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, outsider);
        access.grant_role(outsider_auth, role, outsider);
    });
    let admin_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, admin);
    access.set_role_admin(admin_auth, role, admin_role);
    let admin_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, admin);
    assert_panics(|| access.grant_role(admin_auth, role, outsider));
    let admin_auth = role_auth(&access, DEFAULT_ADMIN_ROLE, admin);
    access.grant_role(admin_auth, admin_role, admin);
    let role_admin_auth = role_auth(&access, admin_role, admin);
    access.grant_role(role_admin_auth, role, outsider);
    assert!(access.has_role(role, outsider));
    let role_admin_auth = role_auth(&access, admin_role, admin);
    access.revoke_role(role_admin_auth, role, outsider);
    assert!(!access.has_role(role, outsider));
    let member_auth = role_auth(&access, role, member);
    access.renounce_role(role, member_auth);
    assert!(!access.has_role(role, member));

    let mut pausable = Pausable::new();
    assert!(!pausable.paused());
    assert_panics(|| pausable.assert_paused());
    pausable.pause();
    assert!(pausable.paused());
    assert_panics(|| pausable.pause());
    assert_panics(|| pausable.assert_not_paused());
    pausable.unpause();
    assert_panics(|| pausable.unpause());
    pausable.assert_not_paused();
}

#[test]
fn threshold_multisig_consumes_approvals_only_after_quorum_success() {
    let owner_a_secret = moonlight_secret(21);
    let owner_b_secret = moonlight_secret(22);
    let outsider_secret = moonlight_secret(23);
    let owner_a = Principal::moonlight(&BlsPublicKey::from(&owner_a_secret));
    let owner_b = Principal::moonlight(&BlsPublicKey::from(&owner_b_secret));
    let outsider = Principal::moonlight(&BlsPublicKey::from(&outsider_secret));

    let mut multisig = ThresholdMultisig::new();
    multisig.init(MultisigConfig {
        owners: vec![owner_a, owner_b],
        threshold: 2,
    });
    let owners = multisig.owners();
    assert_eq!(owners.len(), 2);
    assert!(owners.contains(&owner_a));
    assert!(owners.contains(&owner_b));
    assert_panics(|| {
        multisig.init(MultisigConfig {
            owners: vec![owner_a],
            threshold: 1,
        })
    });

    let signed_b = signed(&owner_b_secret, 0);
    let signed_outsider = signed(&outsider_secret, 0);
    let mut authorizations = AuthorizationManager::new();

    assert_panics(|| {
        multisig.authorize_action(
            &mut authorizations,
            CallContext::from_principal(owner_a),
            &[signed_outsider.clone()],
            envelope(),
            100,
        );
    });
    assert_eq!(authorizations.nonce(outsider, DOMAIN), 0);

    let quorum = multisig.authorize_action(
        &mut authorizations,
        CallContext::from_principal(owner_a),
        &[signed_b.clone()],
        envelope(),
        100,
    );
    assert_eq!(quorum.signers().len(), 2);
    assert!(quorum.signers().contains(&owner_a));
    assert!(quorum.signers().contains(&owner_b));
    assert_eq!(authorizations.nonce(owner_b, DOMAIN), 1);
    assert_panics(|| {
        multisig.authorize_action(
            &mut authorizations,
            CallContext::from_principal(owner_a),
            &[signed_b.clone()],
            envelope(),
            100,
        );
    });
    assert_eq!(authorizations.nonce(owner_b, DOMAIN), 1);

    assert_panics(|| {
        quorum_for(
            &multisig,
            owner_a,
            &[signed(&owner_a_secret, 0), signed_b.clone()],
        )
    });
    assert_panics(|| {
        quorum_for(&multisig, owner_a, &[signed_outsider.clone()])
    });

    let quorum = quorum_for(&multisig, owner_a, &[signed_b.clone()]);
    multisig.add_owner(&quorum, outsider);
    assert!(multisig.is_owner(outsider));
    let quorum = quorum_for(&multisig, owner_a, &[signed_b.clone()]);
    multisig.set_threshold(&quorum, 3);
    assert_eq!(multisig.threshold(), 3);
    let quorum =
        quorum_for(&multisig, owner_a, &[signed_b, signed_outsider.clone()]);
    assert_panics(|| multisig.remove_owner(&quorum, owner_b, 3));
    multisig.remove_owner(&quorum, owner_b, 2);
    assert!(!multisig.is_owner(owner_b));
}

#[test]
fn multisig_controller_lifecycle_replay_and_authority_changes_are_pinned() {
    let owner_a_secret = moonlight_secret(31);
    let owner_b_secret = moonlight_secret(32);
    let owner_c_secret = moonlight_secret(33);
    let owner_a = Principal::moonlight(&BlsPublicKey::from(&owner_a_secret));
    let owner_b = Principal::moonlight(&BlsPublicKey::from(&owner_b_secret));
    let owner_c = Principal::moonlight(&BlsPublicKey::from(&owner_c_secret));
    let outsider = principal(34);
    let operation_id = [35u8; 32];
    let signed_b = signed(&owner_b_secret, 0);
    let signed_c = signed(&owner_c_secret, 0);

    let mut controller = MultisigController::new();
    assert_panics(|| controller.propose(operation_id, target(35), owner_a, 1));
    controller.init(MultisigControllerConfig {
        owners: vec![owner_a, owner_b, owner_c],
        threshold: 2,
        proposal_ttl: 10,
        tombstone_ttl: 20,
    });
    assert!(controller.is_initialized());
    assert_panics(|| {
        controller.init(MultisigControllerConfig {
            owners: vec![owner_a],
            threshold: 1,
            proposal_ttl: 10,
            tombstone_ttl: 20,
        })
    });

    assert_panics(|| controller.propose(operation_id, target(35), outsider, 1));
    let first = controller.propose(operation_id, target(35), owner_a, 1);
    assert_eq!(first.status, MultisigControllerStatus::Proposed);
    assert_eq!(first.confirmations, 1);
    assert!(controller.proposal(operation_id).is_some());
    assert_panics(|| controller.confirm(operation_id, owner_a, 2));
    assert_panics(|| controller.propose(operation_id, target(36), owner_b, 2));

    let ready = controller.confirm(operation_id, owner_b, 2);
    assert_eq!(ready.status, MultisigControllerStatus::Ready);
    assert_eq!(ready.confirmations, 2);
    assert!(ready.ready_operation.is_some());
    assert!(controller.proposal(operation_id).is_none());
    assert_eq!(controller.tombstone_expiry(operation_id), Some(22));
    assert_panics(|| controller.propose(operation_id, target(35), owner_c, 3));

    let expired_id = [36u8; 32];
    controller.propose(expired_id, target(36), owner_a, 3);
    assert_panics(|| controller.confirm(expired_id, owner_b, 14));
    assert!(controller.proposal(expired_id).is_some());
    let replacement_id = [37u8; 32];
    controller.propose(replacement_id, target(37), owner_a, 14);
    assert!(controller.proposal(expired_id).is_none());

    let cancel_id = [38u8; 32];
    controller.propose(cancel_id, target(38), owner_a, 15);
    let quorum =
        controller_quorum_for(&controller, owner_a, &[signed_b.clone()]);
    let cancelled = controller.cancel(cancel_id, &quorum, 16);
    assert_eq!(cancelled.id, cancel_id);
    assert_eq!(cancelled.signers, quorum.signers());
    assert!(controller.proposal(cancel_id).is_none());

    let pending_id = [39u8; 32];
    controller.propose(pending_id, target(39), owner_a, 17);
    let quorum =
        controller_quorum_for(&controller, owner_a, &[signed_b.clone()]);
    let event = controller.update_authority(&quorum, vec![owner_a, owner_c], 2);
    assert!(event.removed_operations.contains(&pending_id));
    assert!(!controller.is_owner(owner_b));
    assert!(controller.is_owner(owner_c));

    let quorum = controller_quorum_for(&controller, owner_a, &[signed_c]);
    let limits = controller.set_time_limits(&quorum, 7, 9);
    assert_eq!(limits.previous_proposal_ttl, 10);
    assert_eq!(controller.proposal_ttl(), 7);
    assert_eq!(controller.tombstone_ttl(), 9);
    assert_panics(|| controller.set_time_limits(&quorum, 0, 9));
}
