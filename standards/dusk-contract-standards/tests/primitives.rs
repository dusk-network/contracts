use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::access::{
    AccessControl, Ownable, Ownable2Step, OwnerSet, Pausable,
    DEFAULT_ADMIN_ROLE,
};
use dusk_contract_standards::auth::{
    ActionEnvelope, AuthorizationManager, AuthorizedAction,
    MoonlightAuthorization, PhoenixSignatureAuthorization, SignedAuthorization,
};
use dusk_contract_standards::core::{
    CallContext, NonceEntry, NonceManager, Principal, PrincipalKind,
    ReplayGuard,
};
use dusk_contract_standards::governance::{
    MultisigConfig, MultisigController, MultisigControllerConfig,
    MultisigControllerStatus, MultisigTarget, ThresholdMultisig, Timelock,
    TimelockController, CANCELLER_ROLE, EXECUTOR_ROLE, PROPOSER_ROLE,
    TIMELOCK_ADMIN_ROLE,
};
use dusk_contract_standards::proxy::{
    StateStore, UpgradeActivated, UpgradeAdmin, UpgradeCancelled,
    UpgradePrepared, UpgradeRolledBack,
};
use dusk_contract_standards::security::ReentrancyGuard;
use dusk_contract_standards::token::drc20::{
    Allowance, ApproveCall, BalanceOf as BalanceOf20, DecreaseAllowanceCall,
    Drc20, IncreaseAllowanceCall, Init as Init20, InitBalance, SupplyCap,
    TransferCall as Transfer20, TransferFromCall, VotingUnits,
};
use dusk_contract_standards::token::drc721::{
    ApproveCall as Approve721, BalanceOf as BalanceOf721, Drc721,
    Init as Init721, InitToken, IsApprovedForAll, OwnerOf, RoyaltyInfo,
    RoyaltyRegistry, SetApprovalForAllCall, TokenByIndex, TokenOfOwnerByIndex,
    TokensOf, TransferFromCall as Transfer721,
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

fn p(byte: u8) -> Principal {
    Principal::phoenix([byte; 32])
}

fn c(byte: u8) -> ContractId {
    ContractId::from_bytes([byte; 32])
}

fn multisig_target(
    contract: u8,
    function: &str,
    args: impl AsRef<[u8]>,
    salt: [u8; 32],
) -> MultisigTarget {
    MultisigTarget {
        call: ContractCall::new(c(contract), function)
            .with_raw_args(args.as_ref().to_vec()),
        salt,
    }
}

fn assert_panics<R>(f: impl FnOnce() -> R) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
}

#[allow(clippy::too_many_arguments)]
fn signed_moonlight_action(
    secret: BlsSecretKey,
    public_key: BlsPublicKey,
    principal: Principal,
    contract: ContractId,
    domain: [u8; 32],
    action_id: [u8; 32],
    payload_hash: [u8; 32],
    nonce: u64,
) -> SignedAuthorization {
    let action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce,
        expires_at: 0,
        principal,
        payload_hash,
    };
    SignedAuthorization::Moonlight(MoonlightAuthorization {
        action,
        public_key,
        signature: secret.sign(&action.message_bytes()),
    })
}

#[allow(clippy::too_many_arguments)]
fn signed_phoenix_action(
    secret: SchnorrSecretKey,
    public_key: SchnorrPublicKey,
    principal: Principal,
    contract: ContractId,
    domain: [u8; 32],
    action_id: [u8; 32],
    payload_hash: [u8; 32],
    nonce: u64,
    rng_seed: u64,
) -> SignedAuthorization {
    let action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce,
        expires_at: 0,
        principal,
        payload_hash,
    };
    let mut rng = StdRng::seed_from_u64(rng_seed);
    SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
        action,
        public_key,
        signature: secret.sign(&mut rng, action.message_hash()),
        replay_key: None,
    })
}

#[test]
fn ownable_positive_and_negative_paths() {
    let owner = p(1);
    let next = p(2);
    let stranger = p(3);

    let mut ownable = Ownable::new();
    ownable.init(owner);
    assert_eq!(ownable.owner(), Some(owner));
    ownable.assert_owner(owner);
    assert_panics(|| ownable.assert_owner(stranger));

    ownable.transfer_ownership(owner, next);
    assert_eq!(ownable.owner(), Some(next));
    assert_panics(|| ownable.transfer_ownership(owner, stranger));
    ownable.renounce_ownership(next);
    assert_eq!(ownable.owner(), None);
}

#[test]
fn ownable_two_step_requires_pending_owner_acceptance() {
    let owner = p(1);
    let next = p(2);
    let stranger = p(3);

    let mut ownable = Ownable2Step::new();
    ownable.init(owner);
    ownable.transfer_ownership(owner, next);
    assert_eq!(ownable.owner(), Some(owner));
    assert_eq!(ownable.pending_owner(), Some(next));

    assert_panics(|| ownable.accept_ownership(stranger));
    ownable.accept_ownership(next);
    assert_eq!(ownable.owner(), Some(next));
    assert_eq!(ownable.pending_owner(), None);
}

#[test]
fn access_control_admin_role_gates_grants_and_revokes() {
    let admin = p(1);
    let minter = p(2);
    let stranger = p(3);
    let minter_role = [7u8; 32];

    let mut access = AccessControl::new();
    access.init_admin(admin);
    assert!(access.has_role(DEFAULT_ADMIN_ROLE, admin));
    assert_panics(|| access.grant_role(stranger, minter_role, minter));

    access.grant_role(admin, minter_role, minter);
    assert!(access.has_role(minter_role, minter));
    access.assert_role(minter_role, minter);

    assert_panics(|| access.revoke_role(stranger, minter_role, minter));
    access.revoke_role(admin, minter_role, minter);
    assert!(!access.has_role(minter_role, minter));

    access.renounce_role(DEFAULT_ADMIN_ROLE, admin);
    assert!(!access.has_role(DEFAULT_ADMIN_ROLE, admin));
    assert_panics(|| access.init_admin(stranger));
}

#[test]
fn owner_set_supports_mixed_dusk_principals() {
    let moonlight = Principal::Moonlight([1u8; 193]);
    let phoenix = p(2);
    let contract = Principal::contract(c(3));
    let stranger = p(4);

    let mut owners = OwnerSet::new();
    owners.init([moonlight, phoenix]);
    assert!(owners.is_owner(moonlight));
    assert!(owners.is_owner(phoenix));
    assert_eq!(owners.count_kind(PrincipalKind::Moonlight), 1);
    assert_eq!(owners.count_kind(PrincipalKind::Phoenix), 1);
    assert_panics(|| owners.assert_owner(stranger));

    owners.add_owner(moonlight, contract);
    assert_eq!(owners.count_kind(PrincipalKind::Contract), 1);
    assert_panics(|| owners.add_owner(stranger, p(5)));

    owners.remove_owner(phoenix, moonlight);
    assert!(!owners.is_owner(moonlight));
    owners.replace_owner(contract, phoenix, moonlight);
    assert!(owners.is_owner(moonlight));
    assert!(!owners.is_owner(phoenix));

    let before = owners.owners();
    assert_panics(|| {
        owners.replace_owner(contract, moonlight, Principal::contract(c(0)));
    });
    assert_eq!(owners.owners(), before);
    assert_panics(|| {
        owners.replace_owner(contract, moonlight, contract);
    });
    assert_eq!(owners.owners(), before);
    assert_panics(|| {
        owners.replace_owner(contract, p(99), p(10));
    });
    assert_eq!(owners.owners(), before);
}

#[test]
fn threshold_multisig_requires_distinct_quorum_before_nonce_consumption() {
    let owner_a_sk = moonlight_secret(101);
    let owner_a_pk = BlsPublicKey::from(&owner_a_sk);
    let owner_a = Principal::moonlight(&owner_a_pk);
    let owner_b_sk = moonlight_secret(102);
    let owner_b_pk = BlsPublicKey::from(&owner_b_sk);
    let owner_b = Principal::moonlight(&owner_b_pk);
    let outsider_sk = moonlight_secret(103);
    let outsider_pk = BlsPublicKey::from(&outsider_sk);
    let outsider = Principal::moonlight(&outsider_pk);

    let contract = c(104);
    let domain = [105u8; 32];
    let action_id = [106u8; 32];
    let payload_hash = [107u8; 32];
    let envelope =
        ActionEnvelope::new(contract, domain, action_id, payload_hash);

    let mut multisig = ThresholdMultisig::new();
    multisig.init(MultisigConfig {
        owners: vec![owner_a, owner_b],
        threshold: 2,
    });

    let approval_a = signed_moonlight_action(
        owner_a_sk,
        owner_a_pk,
        owner_a,
        contract,
        domain,
        action_id,
        payload_hash,
        0,
    );
    let approval_b = signed_moonlight_action(
        owner_b_sk,
        owner_b_pk,
        owner_b,
        contract,
        domain,
        action_id,
        payload_hash,
        0,
    );
    let outsider_approval = signed_moonlight_action(
        outsider_sk,
        outsider_pk,
        outsider,
        contract,
        domain,
        action_id,
        payload_hash,
        0,
    );

    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        multisig.authorize_action(
            &mut manager,
            CallContext::none(),
            std::slice::from_ref(&approval_a),
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(owner_a, domain), 0);

    assert_panics(|| {
        multisig.authorize_action(
            &mut manager,
            CallContext::none(),
            &[approval_a.clone(), approval_a.clone()],
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(owner_a, domain), 0);

    assert_panics(|| {
        multisig.authorize_action(
            &mut manager,
            CallContext::none(),
            &[approval_a.clone(), outsider_approval],
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(owner_a, domain), 0);
    assert_eq!(manager.nonce(outsider, domain), 0);

    let wrong_envelope =
        ActionEnvelope::new(contract, domain, action_id, [108u8; 32]);
    assert_panics(|| {
        multisig.authorize_action(
            &mut manager,
            CallContext::none(),
            &[approval_a.clone(), approval_b.clone()],
            wrong_envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(owner_a, domain), 0);
    assert_eq!(manager.nonce(owner_b, domain), 0);

    let signers = multisig.authorize_action(
        &mut manager,
        CallContext::none(),
        &[approval_a.clone(), approval_b.clone()],
        envelope,
        0,
    );
    assert_eq!(signers.len(), 2);
    assert!(signers.contains(&owner_a));
    assert!(signers.contains(&owner_b));
    assert_eq!(manager.nonce(owner_a, domain), 1);
    assert_eq!(manager.nonce(owner_b, domain), 1);

    assert_panics(|| {
        multisig.authorize_action(
            &mut manager,
            CallContext::none(),
            &[approval_a, approval_b],
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(owner_a, domain), 1);
    assert_eq!(manager.nonce(owner_b, domain), 1);
}

#[test]
fn threshold_multisig_counts_observed_moonlight_and_contract_callers() {
    let contract_owner = Principal::contract(c(110));
    let phoenix_sk = SchnorrSecretKey::from(JubJubScalar::from(111u64));
    let phoenix_pk = SchnorrPublicKey::from(&phoenix_sk);
    let phoenix_owner = Principal::phoenix_public_key(&phoenix_pk);
    let contract = c(112);
    let domain = [113u8; 32];
    let action_id = [114u8; 32];
    let payload_hash = [115u8; 32];
    let envelope =
        ActionEnvelope::new(contract, domain, action_id, payload_hash);

    let mut multisig = ThresholdMultisig::new();
    multisig.init(MultisigConfig {
        owners: vec![contract_owner, phoenix_owner],
        threshold: 2,
    });

    let phoenix_approval = signed_phoenix_action(
        phoenix_sk,
        phoenix_pk,
        phoenix_owner,
        contract,
        domain,
        action_id,
        payload_hash,
        0,
        116,
    );

    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        multisig.authorize_action(
            &mut manager,
            CallContext::from_principal(phoenix_owner),
            &[],
            envelope,
            0,
        );
    });

    let signers = multisig.authorize_action(
        &mut manager,
        CallContext::from_principal(contract_owner),
        &[phoenix_approval],
        envelope,
        0,
    );
    assert_eq!(signers, vec![phoenix_owner, contract_owner]);
    assert_eq!(manager.nonce(phoenix_owner, domain), 1);
}

#[test]
fn threshold_multisig_owner_management_requires_quorum_and_is_atomic() {
    let owner_a = p(120);
    let owner_b = p(121);
    let owner_c = p(122);
    let owner_d = p(123);
    let outsider = p(124);

    let mut multisig = ThresholdMultisig::new();
    multisig.init(MultisigConfig {
        owners: vec![owner_a, owner_b, owner_c],
        threshold: 2,
    });

    assert_panics(|| multisig.set_threshold(&[owner_a], 1));
    assert_eq!(multisig.threshold(), 2);

    assert_panics(|| multisig.add_owner(&[owner_a, outsider], owner_d));
    assert_eq!(multisig.owners(), vec![owner_a, owner_b, owner_c]);

    multisig.add_owner(&[owner_a, owner_b], owner_d);
    assert_eq!(multisig.owners(), vec![owner_a, owner_b, owner_c, owner_d]);

    let before = multisig.owners();
    assert_panics(|| {
        multisig.replace_owner(&[owner_a, owner_b], owner_c, owner_d)
    });
    assert_eq!(multisig.owners(), before);

    assert_panics(|| multisig.remove_owner(&[owner_a, owner_b], owner_d, 4));
    assert_eq!(multisig.owners(), before);
    assert_eq!(multisig.threshold(), 2);

    multisig.remove_owner(&[owner_a, owner_b], owner_d, 2);
    assert_eq!(multisig.owners(), vec![owner_a, owner_b, owner_c]);

    multisig.replace_owner(&[owner_a, owner_b], owner_c, owner_d);
    assert_eq!(multisig.owners(), vec![owner_a, owner_b, owner_d]);

    multisig.set_threshold(&[owner_a, owner_b], 3);
    assert_eq!(multisig.threshold(), 3);
    assert_panics(|| multisig.set_threshold(&[owner_a, owner_b], 0));
    assert_eq!(multisig.threshold(), 3);
}

#[test]
fn multisig_controller_proposes_confirms_executes_and_tombstones() {
    let owner_a = p(130);
    let owner_b = p(131);
    let owner_c = p(132);
    let outsider = p(133);
    let id = [134u8; 32];
    let target = multisig_target(135, "set_value", [1, 2, 3], [136u8; 32]);

    let mut controller = MultisigController::new();
    controller.init(MultisigControllerConfig {
        owners: vec![owner_a, owner_b, owner_c],
        threshold: 2,
        proposal_ttl: 10,
        tombstone_ttl: 5,
    });

    assert_panics(|| controller.confirm(id, owner_a, 0));
    assert_panics(|| controller.propose(id, target.clone(), outsider, 0));
    assert!(controller.proposal(id).is_none());

    let proposed = controller.propose(id, target.clone(), owner_a, 0);
    assert_eq!(proposed.status, MultisigControllerStatus::Proposed);
    assert_eq!(proposed.confirmations, 1);
    assert!(proposed.ready_operation.is_none());
    assert_eq!(
        controller.proposal(id).expect("pending").confirmations,
        vec![owner_a]
    );

    assert_panics(|| controller.confirm(id, owner_a, 1));
    assert_eq!(
        controller
            .proposal(id)
            .expect("still pending")
            .confirmations,
        vec![owner_a]
    );

    let ready = controller.confirm(id, owner_b, 1);
    assert_eq!(ready.status, MultisigControllerStatus::Ready);
    assert_eq!(ready.confirmations, 2);
    let operation = ready.ready_operation.expect("ready operation");
    assert_eq!(operation.target, target);
    assert_eq!(operation.confirmations, vec![owner_a, owner_b]);
    assert!(controller.proposal(id).is_none());
    assert_eq!(controller.tombstone_expiry(id), Some(6));

    assert_panics(|| {
        controller.propose(
            id,
            multisig_target(135, "set_value", [4], [136u8; 32]),
            owner_c,
            2,
        )
    });
    assert_eq!(controller.tombstone_expiry(id), Some(6));

    let reproposed = controller.propose(
        id,
        multisig_target(135, "set_value", [4], [136u8; 32]),
        owner_c,
        7,
    );
    assert_eq!(reproposed.status, MultisigControllerStatus::Proposed);
    assert_eq!(controller.tombstone_expiry(id), None);
}

#[test]
fn multisig_controller_expiry_cancel_and_authority_updates_are_atomic() {
    let owner_a = p(140);
    let owner_b = p(141);
    let owner_c = p(142);
    let owner_d = p(143);
    let outsider = p(144);
    let id_a = [145u8; 32];
    let id_b = [146u8; 32];

    let mut controller = MultisigController::new();
    controller.init(MultisigControllerConfig {
        owners: vec![owner_a, owner_b, owner_c],
        threshold: 2,
        proposal_ttl: 3,
        tombstone_ttl: 4,
    });
    assert_panics(|| {
        controller.init(MultisigControllerConfig {
            owners: vec![owner_a, owner_b],
            threshold: 1,
            proposal_ttl: 1,
            tombstone_ttl: 1,
        });
    });

    controller.propose(
        id_a,
        multisig_target(147, "one", [], [148u8; 32]),
        owner_a,
        10,
    );
    assert!(controller.proposal(id_a).is_some());
    assert_panics(|| controller.confirm(id_a, owner_b, 14));
    assert!(controller.proposal(id_a).is_none());
    controller.propose(
        id_b,
        multisig_target(149, "two", [], [150u8; 32]),
        owner_a,
        14,
    );
    assert!(controller.proposal(id_a).is_none());
    assert!(controller.proposal(id_b).is_some());

    assert_panics(|| controller.cancel(id_b, &[owner_a], 14));
    assert!(controller.proposal(id_b).is_some());
    let cancelled = controller.cancel(id_b, &[owner_a, owner_b], 14);
    assert_eq!(cancelled.signers, vec![owner_a, owner_b]);
    assert!(controller.proposal(id_b).is_none());

    controller.propose(
        id_a,
        multisig_target(151, "three", [], [152u8; 32]),
        owner_a,
        15,
    );
    let before = controller.owners();
    assert_panics(|| {
        controller.update_authority(
            &[owner_a, outsider],
            vec![owner_a, owner_d],
            2,
        );
    });
    assert_eq!(controller.owners(), before);
    assert!(controller.proposal(id_a).is_some());

    let event = controller.update_authority(
        &[owner_a, owner_b],
        vec![owner_a, owner_b, owner_c, owner_d],
        2,
    );
    assert_eq!(event.previous_owners, before);
    assert_eq!(event.owners, vec![owner_a, owner_b, owner_c, owner_d]);
    assert!(event.removed_operations.is_empty());
    assert!(controller.proposal(id_a).is_some());

    let event = controller.update_authority(
        &[owner_a, owner_b],
        vec![owner_a, owner_d],
        2,
    );
    assert_eq!(event.removed_operations, vec![id_a]);
    assert!(controller.proposal(id_a).is_none());

    let before_ttl = controller.proposal_ttl();
    assert_panics(|| controller.set_time_limits(&[owner_a], 0, 4));
    assert_eq!(controller.proposal_ttl(), before_ttl);
    let event = controller.set_time_limits(&[owner_a, owner_d], 8, 9);
    assert_eq!(event.previous_proposal_ttl, 3);
    assert_eq!(event.proposal_ttl, 8);
    assert_eq!(controller.tombstone_ttl(), 9);
}

#[test]
fn multisig_controller_rejects_bad_targets_and_config() {
    let owner_a = p(153);
    let owner_b = p(154);
    let mut controller = MultisigController::new();

    assert_panics(|| {
        controller.init(MultisigControllerConfig {
            owners: vec![owner_a, owner_b],
            threshold: 2,
            proposal_ttl: 0,
            tombstone_ttl: 1,
        });
    });
    assert!(!controller.is_initialized());

    controller.init(MultisigControllerConfig {
        owners: vec![owner_a, owner_b],
        threshold: 2,
        proposal_ttl: 1,
        tombstone_ttl: 1,
    });

    assert_panics(|| {
        controller.propose(
            [155u8; 32],
            multisig_target(0, "call", [], [156u8; 32]),
            owner_a,
            0,
        );
    });
    assert_panics(|| {
        controller.propose(
            [157u8; 32],
            multisig_target(158, "", [], [159u8; 32]),
            owner_a,
            0,
        );
    });
}

#[test]
fn replay_guard_rejects_reuse_across_same_principal() {
    let owner = p(1);
    let other = p(2);
    let key = [9u8; 32];

    let mut replay = ReplayGuard::new();
    assert!(!replay.is_used(owner, key));
    replay.consume(owner, key);
    assert!(replay.is_used(owner, key));
    replay.consume(other, key);
    assert_panics(|| replay.consume(owner, key));
}

#[test]
fn nonce_manager_keeps_independent_principal_and_domain_streams() {
    let moonlight = Principal::Moonlight([1u8; 193]);
    let phoenix = p(2);
    let permit_domain = [10u8; 32];
    let vote_domain = [11u8; 32];

    let mut nonces = NonceManager::new();
    assert_eq!(nonces.current(moonlight, permit_domain), 0);
    assert_eq!(nonces.use_next(moonlight, permit_domain), 0);
    assert_eq!(nonces.current(moonlight, permit_domain), 1);
    assert_eq!(nonces.current(phoenix, permit_domain), 0);
    assert_eq!(nonces.current(moonlight, vote_domain), 0);

    assert_panics(|| {
        nonces.consume(moonlight, permit_domain, 0);
    });
    nonces.invalidate_until(moonlight, permit_domain, 9);
    assert_eq!(nonces.current(moonlight, permit_domain), 9);
    assert_panics(|| {
        nonces.invalidate_until(moonlight, permit_domain, 8);
    });

    nonces.import_entries([NonceEntry {
        principal: moonlight,
        domain: permit_domain,
        nonce: 12,
    }]);
    assert_eq!(nonces.current(moonlight, permit_domain), 12);
}

#[test]
fn authorization_manager_verifies_moonlight_and_phoenix_paths() {
    let sk = moonlight_secret(7);
    let pk = BlsPublicKey::from(&sk);
    let moonlight = Principal::moonlight(&pk);
    let contract = c(33);
    let domain = [44u8; 32];
    let action_id = [55u8; 32];

    let action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce: 0,
        expires_at: 100,
        principal: moonlight,
        payload_hash: [66u8; 32],
    };
    let signature = sk.sign(&action.message_bytes());
    let auth = MoonlightAuthorization {
        action,
        public_key: pk,
        signature,
    };

    let mut authorizations = AuthorizationManager::new();
    assert_eq!(authorizations.authorize_moonlight(&auth, 99), moonlight);
    assert_eq!(authorizations.nonce(moonlight, domain), 1);
    assert_panics(|| {
        authorizations.authorize_moonlight(&auth, 99);
    });

    let bad_action = AuthorizedAction {
        nonce: 1,
        principal: p(99),
        ..action
    };
    let bad_signature = sk.sign(&bad_action.message_bytes());
    let bad_auth = MoonlightAuthorization {
        action: bad_action,
        public_key: pk,
        signature: bad_signature,
    };
    assert_panics(|| {
        authorizations.authorize_moonlight(&bad_auth, 99);
    });

    let mut rng = StdRng::seed_from_u64(1234);
    let phoenix_sk = SchnorrSecretKey::from(JubJubScalar::from(88u64));
    let phoenix_pk = SchnorrPublicKey::from(&phoenix_sk);
    let phoenix = Principal::phoenix_public_key(&phoenix_pk);
    let phoenix_action = AuthorizedAction {
        contract,
        domain: [77u8; 32],
        action_id,
        nonce: 0,
        expires_at: 0,
        principal: phoenix,
        payload_hash: [22u8; 32],
    };
    let phoenix_auth = PhoenixSignatureAuthorization {
        action: phoenix_action,
        public_key: phoenix_pk,
        signature: phoenix_sk.sign(&mut rng, phoenix_action.message_hash()),
        replay_key: Some([99u8; 32]),
    };
    assert_eq!(authorizations.authorize_phoenix(&phoenix_auth, 1), phoenix);
    assert_eq!(authorizations.nonce(phoenix, [77u8; 32]), 1);
    assert!(authorizations.replay_used(phoenix, [99u8; 32]));

    let expired_action = AuthorizedAction {
        expires_at: 9,
        nonce: 1,
        ..phoenix_action
    };
    let expired = PhoenixSignatureAuthorization {
        action: expired_action,
        public_key: phoenix_pk,
        signature: phoenix_sk.sign(&mut rng, expired_action.message_hash()),
        replay_key: None,
    };
    assert_panics(|| {
        authorizations.authorize_phoenix(&expired, 10);
    });

    let bad_signature_action = AuthorizedAction {
        nonce: 1,
        payload_hash: [23u8; 32],
        ..phoenix_action
    };
    let bad_signature = PhoenixSignatureAuthorization {
        action: bad_signature_action,
        public_key: phoenix_pk,
        signature: phoenix_sk.sign(&mut rng, phoenix_action.message_hash()),
        replay_key: None,
    };
    assert_panics(|| {
        authorizations.authorize_phoenix(&bad_signature, 1);
    });
    assert_eq!(authorizations.nonce(phoenix, [77u8; 32]), 1);

    let replay_action = AuthorizedAction {
        nonce: 1,
        payload_hash: [24u8; 32],
        ..phoenix_action
    };
    let replay = PhoenixSignatureAuthorization {
        action: replay_action,
        public_key: phoenix_pk,
        signature: phoenix_sk.sign(&mut rng, replay_action.message_hash()),
        replay_key: Some([99u8; 32]),
    };
    assert_panics(|| {
        authorizations.authorize_phoenix(&replay, 1);
    });
    assert_eq!(authorizations.nonce(phoenix, [77u8; 32]), 1);

    let wrong_sk = SchnorrSecretKey::from(JubJubScalar::from(89u64));
    let wrong_pk = SchnorrPublicKey::from(&wrong_sk);
    let wrong_key = PhoenixSignatureAuthorization {
        action: AuthorizedAction {
            nonce: 1,
            ..phoenix_action
        },
        public_key: wrong_pk,
        signature: wrong_sk.sign(&mut rng, phoenix_action.message_hash()),
        replay_key: None,
    };
    assert_panics(|| {
        authorizations.authorize_phoenix(&wrong_key, 1);
    });

    let bounded_domain = [88u8; 32];
    let bounded_action = AuthorizedAction {
        contract,
        domain: bounded_domain,
        action_id,
        nonce: 0,
        expires_at: 10,
        principal: moonlight,
        payload_hash: [1u8; 32],
    };
    let bounded_signed =
        SignedAuthorization::Moonlight(MoonlightAuthorization {
            action: bounded_action,
            public_key: pk,
            signature: sk.sign(&bounded_action.message_bytes()),
        });
    let mut bounded = AuthorizationManager::new();
    assert_panics(|| {
        bounded.authorize_signed_action(
            &bounded_signed,
            ActionEnvelope::new(contract, bounded_domain, action_id, [2u8; 32]),
            9,
        );
    });
    assert_eq!(bounded.nonce(moonlight, bounded_domain), 0);
    assert_eq!(
        bounded.authorize_signed_action(
            &bounded_signed,
            ActionEnvelope::new(contract, bounded_domain, action_id, [1u8; 32]),
            10,
        ),
        moonlight
    );
    assert_eq!(bounded.nonce(moonlight, bounded_domain), 1);

    let expired_bounded_action = AuthorizedAction {
        nonce: 1,
        expires_at: 10,
        payload_hash: [3u8; 32],
        ..bounded_action
    };
    let expired_bounded =
        SignedAuthorization::Moonlight(MoonlightAuthorization {
            action: expired_bounded_action,
            public_key: pk,
            signature: sk.sign(&expired_bounded_action.message_bytes()),
        });
    assert_panics(|| {
        bounded.authorize_signed_action(
            &expired_bounded,
            ActionEnvelope::new(contract, bounded_domain, action_id, [3u8; 32]),
            11,
        );
    });
    assert_eq!(bounded.nonce(moonlight, bounded_domain), 1);
}

#[test]
fn observed_or_signed_authorization_wraps_owner_role_and_admin_checks() {
    let moonlight_sk = moonlight_secret(17);
    let moonlight_pk = BlsPublicKey::from(&moonlight_sk);
    let moonlight = Principal::moonlight(&moonlight_pk);
    let contract_principal = Principal::contract(c(44));
    let contract = c(45);
    let domain = [46u8; 32];
    let action_id = [47u8; 32];

    let mut manager = AuthorizationManager::new();
    assert_eq!(
        manager.authorize_principal(
            moonlight,
            CallContext::from_principal(moonlight),
            None,
            0,
        ),
        moonlight
    );
    assert_eq!(
        manager.authorize_principal(
            contract_principal,
            CallContext::from_principal(contract_principal),
            None,
            0,
        ),
        contract_principal
    );

    let moonlight_action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce: 0,
        expires_at: 0,
        principal: moonlight,
        payload_hash: [48u8; 32],
    };
    let moonlight_signed =
        SignedAuthorization::Moonlight(MoonlightAuthorization {
            action: moonlight_action,
            public_key: moonlight_pk,
            signature: moonlight_sk.sign(&moonlight_action.message_bytes()),
        });
    assert_eq!(
        manager.authorize_principal(
            moonlight,
            CallContext::none(),
            Some(&moonlight_signed),
            0,
        ),
        moonlight
    );

    let mut rng = StdRng::seed_from_u64(9876);
    let phoenix_sk = SchnorrSecretKey::from(JubJubScalar::from(18u64));
    let phoenix_pk = SchnorrPublicKey::from(&phoenix_sk);
    let phoenix = Principal::phoenix_public_key(&phoenix_pk);
    let phoenix_action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce: 0,
        expires_at: 0,
        principal: phoenix,
        payload_hash: [49u8; 32],
    };
    let phoenix_signed =
        SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
            action: phoenix_action,
            public_key: phoenix_pk,
            signature: phoenix_sk.sign(&mut rng, phoenix_action.message_hash()),
            replay_key: None,
        });

    let mut ownable = Ownable::new();
    ownable.init(phoenix);
    assert_eq!(
        ownable.authorize_owner_action(
            &mut manager,
            CallContext::none(),
            Some(&phoenix_signed),
            ActionEnvelope::new(contract, domain, action_id, [49u8; 32]),
            0,
        ),
        phoenix
    );

    let mut access = AccessControl::new();
    let role = [50u8; 32];
    access.init_admin(moonlight);
    access.grant_role(moonlight, role, phoenix);
    let phoenix_action = AuthorizedAction {
        nonce: 1,
        payload_hash: [51u8; 32],
        ..phoenix_action
    };
    let phoenix_signed =
        SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
            action: phoenix_action,
            public_key: phoenix_pk,
            signature: phoenix_sk.sign(&mut rng, phoenix_action.message_hash()),
            replay_key: None,
        });
    assert_eq!(
        access.authorize_role_action(
            role,
            &mut manager,
            CallContext::none(),
            Some(&phoenix_signed),
            ActionEnvelope::new(contract, domain, action_id, [51u8; 32]),
            0,
        ),
        phoenix
    );

    let upgrade = UpgradeAdmin::new(phoenix, c(52), 0, 0);
    let phoenix_action = AuthorizedAction {
        nonce: 2,
        payload_hash: [53u8; 32],
        ..phoenix_action
    };
    let phoenix_signed =
        SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
            action: phoenix_action,
            public_key: phoenix_pk,
            signature: phoenix_sk.sign(&mut rng, phoenix_action.message_hash()),
            replay_key: None,
        });
    assert_eq!(
        upgrade.authorize_admin_action(
            &mut manager,
            CallContext::none(),
            Some(&phoenix_signed),
            ActionEnvelope::new(contract, domain, action_id, [53u8; 32]),
            0,
        ),
        phoenix
    );
    assert_panics(|| {
        manager.authorize_principal(
            phoenix,
            CallContext::from_principal(phoenix),
            None,
            0,
        );
    });
}

#[test]
fn failed_owner_role_and_admin_signed_checks_do_not_consume_nonce() {
    let signer_sk = moonlight_secret(70);
    let signer_pk = BlsPublicKey::from(&signer_sk);
    let signer = Principal::moonlight(&signer_pk);
    let owner = p(71);
    let admin = p(72);
    let contract = c(73);
    let implementation = c(74);
    let role = [75u8; 32];
    let domain = [76u8; 32];
    let action_id = [77u8; 32];
    let payload_hash = [78u8; 32];
    let envelope =
        ActionEnvelope::new(contract, domain, action_id, payload_hash);
    let action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce: 0,
        expires_at: 0,
        principal: signer,
        payload_hash,
    };
    let signed = SignedAuthorization::Moonlight(MoonlightAuthorization {
        action,
        public_key: signer_pk,
        signature: signer_sk.sign(&action.message_bytes()),
    });

    let mut manager = AuthorizationManager::new();
    assert_panics(|| {
        manager.authorize_principal_action(
            owner,
            CallContext::none(),
            Some(&signed),
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(signer, domain), 0);

    let mut access = AccessControl::new();
    access.init_admin(admin);
    access.grant_role(admin, role, owner);
    assert_panics(|| {
        access.authorize_role_action(
            role,
            &mut manager,
            CallContext::none(),
            Some(&signed),
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(signer, domain), 0);

    let upgrades = UpgradeAdmin::new(admin, implementation, 0, 0);
    assert_panics(|| {
        upgrades.authorize_admin_action(
            &mut manager,
            CallContext::none(),
            Some(&signed),
            envelope,
            0,
        );
    });
    assert_eq!(manager.nonce(signer, domain), 0);
}

#[test]
fn reentrancy_guard_blocks_nested_entry() {
    let mut guard = ReentrancyGuard::new();
    guard.enter();
    assert_panics(|| guard.enter());
    guard.exit();
    guard.enter();
    guard.exit();
}

#[test]
fn reentrancy_guard_run_resets_after_panic() {
    let mut guard = ReentrancyGuard::new();
    assert_panics(|| {
        guard.run(|| panic!("boom"));
    });
    assert!(!guard.entered());
    guard.enter();
    guard.exit();
}

#[test]
fn timelock_schedules_executes_and_rejects_invalid_states() {
    let op = [8u8; 32];
    let mut timelock = Timelock::new(5);

    let ready_at = timelock.schedule(op, 10, vec![1, 2, 3]);
    assert_eq!(ready_at, 15);
    assert!(!timelock.is_ready(op, 14));
    assert_panics(|| {
        timelock.execute(op, 14);
    });
    assert_eq!(timelock.execute(op, 15), vec![1, 2, 3]);
    assert_panics(|| {
        timelock.execute(op, 16);
    });

    let other = [9u8; 32];
    timelock.schedule(other, 20, vec![]);
    timelock.cancel(other);
    assert!(timelock.get(other).is_none());
}

#[test]
fn timelock_controller_gates_schedule_execute_cancel_and_policy() {
    let admin = p(1);
    let proposer = p(2);
    let executor = p(3);
    let canceller = p(4);
    let stranger = p(5);
    let controller_principal = p(6);
    let op = [10u8; 32];

    let mut controller =
        TimelockController::new(controller_principal, admin, 5);
    assert_eq!(controller.self_principal(), controller_principal);
    assert!(controller.has_role(TIMELOCK_ADMIN_ROLE, admin));
    controller.grant_role(admin, PROPOSER_ROLE, proposer);
    controller.grant_role(admin, EXECUTOR_ROLE, executor);
    controller.grant_role(admin, CANCELLER_ROLE, canceller);

    assert_panics(|| {
        controller.schedule(stranger, op, 10, vec![]);
    });
    assert_eq!(controller.schedule(proposer, op, 10, vec![1]), 15);
    assert_panics(|| {
        controller.execute(executor, op, 14);
    });
    assert_eq!(controller.execute(executor, op, 15), vec![1]);
    assert_panics(|| {
        controller.execute(executor, op, 16);
    });

    let other = [11u8; 32];
    controller.schedule(admin, other, 20, vec![2]);
    assert_panics(|| {
        controller.cancel(stranger, other);
    });
    controller.cancel(canceller, other);
    assert!(controller.get(other).is_none());

    assert_panics(|| controller.set_min_delay(stranger, 9));
    assert_panics(|| controller.set_min_delay(admin, 9));
    let delay_change = [12u8; 32];
    assert_eq!(
        controller.schedule_min_delay_change(proposer, delay_change, 20, 9),
        25
    );
    assert_panics(|| {
        controller.execute_min_delay_change(executor, delay_change, 24);
    });
    assert_eq!(
        controller.execute_min_delay_change(executor, delay_change, 25),
        9
    );
    assert_eq!(controller.timelock().min_delay(), 9);
}

#[test]
fn pausable_tracks_state_and_assertions() {
    let mut pausable = Pausable::new();
    pausable.assert_not_paused();
    assert_panics(|| pausable.assert_paused());
    pausable.pause();
    pausable.assert_paused();
    assert_panics(|| pausable.assert_not_paused());
    pausable.unpause();
    pausable.assert_not_paused();
}

#[test]
fn drc20_rejects_use_before_init_and_double_init() {
    let owner = p(1);
    let mut token = Drc20::new();

    assert_panics(|| {
        token.balance_of(BalanceOf20 { account: owner });
    });
    assert_panics(|| {
        token.mint(owner, 1);
    });

    token.init(Init20 {
        name: "Dusk Token".into(),
        symbol: "DUSKX".into(),
        decimals: 9,
        initial_balances: vec![],
    });
    assert_eq!(token.total_supply(), 0);
    assert_panics(|| {
        token.init(Init20 {
            name: "Again".into(),
            symbol: "AGAIN".into(),
            decimals: 9,
            initial_balances: vec![],
        });
    });

    let mut bad = Drc20::new();
    assert_panics(|| {
        bad.init(Init20 {
            name: "Bad".into(),
            symbol: "BAD".into(),
            decimals: 9,
            initial_balances: vec![InitBalance {
                account: p(0),
                amount: 1,
            }],
        });
    });
    assert_panics(|| {
        bad.total_supply();
    });
    bad.init(Init20 {
        name: "Recovered".into(),
        symbol: "GOOD".into(),
        decimals: 9,
        initial_balances: vec![],
    });
    assert_eq!(bad.total_supply(), 0);

    let mut overflowing = Drc20::new();
    assert_panics(|| {
        overflowing.init(Init20 {
            name: "Overflow".into(),
            symbol: "OVR".into(),
            decimals: 9,
            initial_balances: vec![
                InitBalance {
                    account: owner,
                    amount: u64::MAX,
                },
                InitBalance {
                    account: p(2),
                    amount: 1,
                },
            ],
        });
    });
    assert_panics(|| {
        overflowing.total_supply();
    });
}

#[test]
fn drc20_supports_transfer_allowance_mint_and_burn() {
    let owner = p(1);
    let receiver = p(2);
    let spender = p(3);

    let mut token = Drc20::new();
    let mint_events = token.init(Init20 {
        name: "Dusk Token".into(),
        symbol: "DUSKX".into(),
        decimals: 9,
        initial_balances: vec![InitBalance {
            account: owner,
            amount: 100,
        }],
    });
    assert_eq!(mint_events.len(), 1);
    assert_eq!(token.total_supply(), 100);
    assert_eq!(token.balance_of(BalanceOf20 { account: owner }), 100);

    let transfer = token.transfer(
        owner,
        Transfer20 {
            to: receiver,
            amount: 40,
        },
    );
    assert_eq!(transfer.from, owner);
    assert_eq!(token.balance_of(BalanceOf20 { account: owner }), 60);
    assert_eq!(token.balance_of(BalanceOf20 { account: receiver }), 40);

    let approval = token.approve(
        receiver,
        ApproveCall {
            spender,
            amount: 15,
        },
    );
    assert_eq!(approval.owner, receiver);
    assert_eq!(
        token.allowance(Allowance {
            owner: receiver,
            spender,
        }),
        15
    );
    let increased = token.increase_allowance(
        receiver,
        IncreaseAllowanceCall {
            spender,
            added_amount: 5,
        },
    );
    assert_eq!(increased.amount, 20);
    let decreased = token.decrease_allowance(
        receiver,
        DecreaseAllowanceCall {
            spender,
            subtracted_amount: 5,
        },
    );
    assert_eq!(decreased.amount, 15);

    token.transfer_from(
        spender,
        TransferFromCall {
            owner: receiver,
            to: owner,
            amount: 10,
        },
    );
    assert_eq!(
        token.allowance(Allowance {
            owner: receiver,
            spender,
        }),
        5
    );
    assert_eq!(token.balance_of(BalanceOf20 { account: owner }), 70);

    token.mint(receiver, 5);
    assert_eq!(token.total_supply(), 105);
    token.burn(receiver, 5);
    assert_eq!(token.total_supply(), 100);

    assert_panics(|| {
        token.transfer(
            receiver,
            Transfer20 {
                to: owner,
                amount: 1_000,
            },
        );
    });
    assert_panics(|| {
        token.decrease_allowance(
            receiver,
            DecreaseAllowanceCall {
                spender,
                subtracted_amount: 100,
            },
        );
    });
    assert_panics(|| {
        token.transfer_from(
            spender,
            TransferFromCall {
                owner: receiver,
                to: owner,
                amount: 10,
            },
        );
    });
}

#[test]
fn drc20_failed_operations_do_not_leave_partial_state() {
    let owner = p(1);
    let receiver = p(2);
    let spender = p(3);
    let zero = p(0);

    let mut token = Drc20::new();
    token.init(Init20 {
        name: "Dusk Token".into(),
        symbol: "DUSKX".into(),
        decimals: 9,
        initial_balances: vec![InitBalance {
            account: owner,
            amount: 10,
        }],
    });
    token.approve(owner, ApproveCall { spender, amount: 7 });
    assert_panics(|| {
        token.transfer_from(
            spender,
            TransferFromCall {
                owner,
                to: zero,
                amount: 3,
            },
        );
    });
    assert_eq!(
        token.allowance(Allowance { owner, spender }),
        7,
        "zero-recipient transfer_from must not spend allowance"
    );
    assert_eq!(token.balance_of(BalanceOf20 { account: owner }), 10);

    let empty_owner = p(4);
    token.approve_for(empty_owner, ApproveCall { spender, amount: 7 });
    assert_panics(|| {
        token.transfer_from(
            spender,
            TransferFromCall {
                owner: empty_owner,
                to: receiver,
                amount: 3,
            },
        );
    });
    assert_eq!(
        token.allowance(Allowance {
            owner: empty_owner,
            spender,
        }),
        7,
        "failed transfer_from must not spend allowance before balance checks"
    );
    assert_eq!(token.balance_of(BalanceOf20 { account: receiver }), 0);

    let mut max_supply = Drc20::new();
    max_supply.init(Init20 {
        name: "Max".into(),
        symbol: "MAX".into(),
        decimals: 9,
        initial_balances: vec![InitBalance {
            account: owner,
            amount: u64::MAX,
        }],
    });
    max_supply.transfer(
        owner,
        Transfer20 {
            to: owner,
            amount: 1,
        },
    );
    assert_eq!(
        max_supply.balance_of(BalanceOf20 { account: owner }),
        u64::MAX
    );
    assert_panics(|| {
        max_supply.mint(receiver, 1);
    });
    assert_eq!(max_supply.total_supply(), u64::MAX);
    assert_eq!(max_supply.balance_of(BalanceOf20 { account: receiver }), 0);
}

#[test]
fn drc20_supply_cap_and_voting_units_cover_policy_hooks() {
    let owner = p(1);
    let receiver = p(2);

    let mut cap = SupplyCap::new(100);
    cap.assert_mint(90, 10);
    assert_eq!(cap.remaining(40), 60);
    assert_panics(|| cap.assert_mint(90, 11));
    assert_panics(|| cap.set_cap(80, 79));
    cap.set_cap(80, 120);
    assert_eq!(cap.cap(), 120);

    let mut votes = VotingUnits::new();
    votes.move_units(None, Some(owner), 100, 10);
    assert_eq!(votes.latest_votes(owner), 100);
    assert_eq!(votes.latest_total_supply(), 100);
    assert_eq!(votes.past_votes(owner, 9), 0);
    assert_eq!(votes.past_votes(owner, 10), 100);

    votes.move_units(Some(owner), Some(receiver), 40, 11);
    assert_eq!(votes.latest_votes(owner), 60);
    assert_eq!(votes.latest_votes(receiver), 40);
    assert_eq!(votes.latest_total_supply(), 100);
    assert_eq!(votes.past_votes(owner, 10), 100);
    assert_eq!(votes.past_votes(owner, 11), 60);

    votes.move_units(Some(receiver), None, 5, 12);
    assert_eq!(votes.latest_votes(receiver), 35);
    assert_eq!(votes.latest_total_supply(), 95);
    assert_eq!(votes.past_total_supply(11), 100);
    assert_eq!(votes.past_total_supply(12), 95);

    assert_panics(|| votes.move_units(Some(receiver), None, 100, 13));
    assert_panics(|| votes.write_votes(owner, 9, 1));
}

#[test]
fn drc721_rejects_use_before_init_and_double_init() {
    let owner = p(1);
    let mut token = Drc721::new();

    assert_panics(|| {
        token.owner_of(OwnerOf { token_id: 1 });
    });
    assert_panics(|| {
        token.mint(owner, 1);
    });

    token.init(Init721 {
        name: "Dusk NFT".into(),
        symbol: "DNFT".into(),
        base_uri: String::new(),
        initial_tokens: vec![],
    });
    assert_eq!(token.total_supply(), 0);
    assert_panics(|| {
        token.init(Init721 {
            name: "Again".into(),
            symbol: "AGAIN".into(),
            base_uri: String::new(),
            initial_tokens: vec![],
        });
    });

    let mut bad = Drc721::new();
    assert_panics(|| {
        bad.init(Init721 {
            name: "Bad".into(),
            symbol: "BAD".into(),
            base_uri: String::new(),
            initial_tokens: vec![InitToken {
                account: p(0),
                token_id: 1,
            }],
        });
    });
    assert_panics(|| {
        bad.total_supply();
    });
    bad.init(Init721 {
        name: "Recovered".into(),
        symbol: "GOOD".into(),
        base_uri: String::new(),
        initial_tokens: vec![],
    });
    assert_eq!(bad.total_supply(), 0);

    let mut duplicate = Drc721::new();
    assert_panics(|| {
        duplicate.init(Init721 {
            name: "Duplicate".into(),
            symbol: "DUP".into(),
            base_uri: String::new(),
            initial_tokens: vec![
                InitToken {
                    account: owner,
                    token_id: 1,
                },
                InitToken {
                    account: p(2),
                    token_id: 1,
                },
            ],
        });
    });
    assert_panics(|| {
        duplicate.total_supply();
    });
}

#[test]
fn drc721_supports_approval_operator_transfer_and_burn() {
    let owner = p(1);
    let receiver = p(2);
    let approved = p(3);
    let operator = p(4);

    let mut token = Drc721::new();
    let events = token.init(Init721 {
        name: "Dusk NFT".into(),
        symbol: "DNFT".into(),
        base_uri: "ipfs://collection/".into(),
        initial_tokens: vec![InitToken {
            account: owner,
            token_id: 1,
        }],
    });
    assert_eq!(events.len(), 1);
    assert_eq!(token.total_supply(), 1);
    assert_eq!(token.owner_of(OwnerOf { token_id: 1 }), owner);
    assert_eq!(token.balance_of(BalanceOf721 { account: owner }), 1);
    assert_eq!(token.token_by_index(TokenByIndex { index: 0 }), 1);
    assert_eq!(
        token.token_of_owner_by_index(TokenOfOwnerByIndex { owner, index: 0 }),
        1
    );
    assert_eq!(token.tokens_of(TokensOf { owner }), vec![1]);

    token.approve(
        owner,
        Approve721 {
            approved,
            token_id: 1,
        },
    );
    token.transfer_from(
        approved,
        Transfer721 {
            from: owner,
            to: receiver,
            token_id: 1,
        },
    );
    assert_eq!(token.owner_of(OwnerOf { token_id: 1 }), receiver);
    assert_eq!(token.balance_of(BalanceOf721 { account: owner }), 0);
    assert_eq!(token.balance_of(BalanceOf721 { account: receiver }), 1);
    assert_eq!(token.tokens_of(TokensOf { owner }), Vec::<u64>::new());
    assert_eq!(token.tokens_of(TokensOf { owner: receiver }), vec![1]);

    token.set_approval_for_all(
        receiver,
        SetApprovalForAllCall {
            operator,
            approved: true,
        },
    );
    assert!(token.is_approved_for_all(IsApprovedForAll {
        owner: receiver,
        operator,
    }));

    token.mint(owner, 2);
    token.burn(owner, 2);
    assert_eq!(token.total_supply(), 1);

    assert_panics(|| {
        token.transfer_from(
            owner,
            Transfer721 {
                from: receiver,
                to: owner,
                token_id: 1,
            },
        );
    });
    assert_panics(|| {
        token.owner_of(OwnerOf { token_id: 2 });
    });
}

#[test]
fn drc721_royalty_registry_quotes_default_and_token_overrides() {
    let default_receiver = p(7);
    let token_receiver = p(8);
    let mut royalties = RoyaltyRegistry::new();

    let empty = royalties.royalty_info(1, 10_000);
    assert_eq!(
        empty.receiver,
        dusk_contract_standards::token::drc721::ZERO_PRINCIPAL
    );
    assert_eq!(empty.amount, 0);

    royalties.set_default_royalty(RoyaltyInfo {
        receiver: default_receiver,
        basis_points: 500,
    });
    assert_eq!(royalties.royalty_info(1, 10_000).amount, 500);
    assert_eq!(royalties.royalty_info(1, 10_000).receiver, default_receiver);

    royalties.set_token_royalty(
        1,
        RoyaltyInfo {
            receiver: token_receiver,
            basis_points: 1_250,
        },
    );
    let quote = royalties.royalty_info(1, 8_000);
    assert_eq!(quote.receiver, token_receiver);
    assert_eq!(quote.amount, 1_000);

    royalties.clear_token_royalty(1);
    assert_eq!(royalties.royalty_info(1, 10_000).receiver, default_receiver);
    royalties.clear_default_royalty();
    assert_eq!(royalties.royalty_info(1, 10_000).amount, 0);

    assert_panics(|| {
        royalties.set_default_royalty(RoyaltyInfo {
            receiver: dusk_contract_standards::token::drc721::ZERO_PRINCIPAL,
            basis_points: 1,
        });
    });
    assert_panics(|| {
        royalties.set_default_royalty(RoyaltyInfo {
            receiver: default_receiver,
            basis_points: 10_001,
        });
    });
}

#[test]
fn proxy_upgrade_admin_enforces_delay_and_rollback_window() {
    let admin = p(1);
    let stranger = p(2);
    let implementation_a = c(10);
    let implementation_b = c(11);

    assert_panics(|| {
        UpgradeAdmin::new(p(0), implementation_a, 0, 0);
    });
    assert_panics(|| {
        UpgradeAdmin::new(admin, c(0), 0, 0);
    });

    let mut upgrades = UpgradeAdmin::new(admin, implementation_a, 5, 10);
    assert_eq!(upgrades.implementation(), implementation_a);
    assert_panics(|| {
        upgrades.prepare(stranger, implementation_b, 0, vec![]);
    });

    assert_eq!(
        upgrades.prepare(admin, implementation_b, 100, vec![1, 2, 3]),
        UpgradePrepared {
            implementation: implementation_b,
            eta: 105,
        }
    );
    assert_panics(|| {
        upgrades.activate(admin, 104);
    });
    let (migration, activated) = upgrades.activate_with_event(admin, 105);
    assert_eq!(migration, vec![1, 2, 3]);
    assert_eq!(
        activated,
        UpgradeActivated {
            previous_implementation: implementation_a,
            implementation: implementation_b,
            rollback_deadline: 115,
        }
    );
    assert_eq!(upgrades.implementation(), implementation_b);
    assert_eq!(upgrades.rollback_deadline(), 115);

    assert_eq!(
        upgrades.rollback_with_event(admin, 110),
        UpgradeRolledBack {
            from_implementation: implementation_b,
            restored_implementation: implementation_a,
        }
    );
    assert_eq!(upgrades.implementation(), implementation_a);

    upgrades.prepare(admin, implementation_b, 200, vec![]);
    assert_eq!(
        upgrades.cancel_pending(admin),
        UpgradeCancelled {
            implementation: implementation_b,
        }
    );
    assert_panics(|| {
        upgrades.activate(admin, 205);
    });

    upgrades.prepare(admin, implementation_b, 200, vec![]);
    upgrades.activate(admin, 205);
    assert_panics(|| upgrades.rollback(admin, 216));
    upgrades.finalize_rollback_window(admin, 216);
    assert_eq!(upgrades.rollback_deadline(), 0);

    let mut delay_overflow = UpgradeAdmin::new(admin, implementation_a, 1, 0);
    assert_panics(|| {
        delay_overflow.prepare(admin, implementation_b, u64::MAX, vec![]);
    });
    assert_eq!(delay_overflow.implementation(), implementation_a);

    let mut rollback_overflow =
        UpgradeAdmin::new(admin, implementation_a, 0, 1);
    rollback_overflow.prepare(admin, implementation_b, u64::MAX, vec![]);
    assert_panics(|| {
        rollback_overflow.activate(admin, u64::MAX);
    });
    assert_eq!(rollback_overflow.implementation(), implementation_a);
    assert!(rollback_overflow.pending().is_some());
}

#[test]
fn proxy_state_store_keeps_plain_and_namespaced_state_separate() {
    let namespace_a = [1u8; 32];
    let namespace_b = [2u8; 32];
    let key = [3u8; 32];
    let word = [4u8; 32];
    let other_word = [5u8; 32];

    let mut store = StateStore::new();
    store.set_word(key, word);
    store.set_namespaced_word(namespace_a, key, other_word);
    store.set_namespaced_bytes(namespace_a, key, vec![1, 2, 3]);

    assert_eq!(store.get_word(key), word);
    assert_eq!(store.get_namespaced_word(namespace_a, key), other_word);
    assert_eq!(store.get_namespaced_word(namespace_b, key), [0u8; 32]);
    assert_eq!(store.get_namespaced_bytes(namespace_a, key), vec![1, 2, 3]);
    assert_eq!(
        store.get_namespaced_bytes(namespace_b, key),
        Vec::<u8>::new()
    );

    store.delete_namespaced(namespace_a, key);
    assert_eq!(store.get_namespaced_word(namespace_a, key), [0u8; 32]);
    assert_eq!(store.get_word(key), word);

    store.delete(key);
    assert_eq!(store.get_word(key), [0u8; 32]);
}
