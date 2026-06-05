// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::auth::AuthorizationManager;
use dusk_contract_standards::core::{CallContext, Principal};
use dusk_contract_standards::governance::{
    Timelock, TimelockController, CANCELLER_ROLE, EXECUTOR_ROLE, PROPOSER_ROLE,
    TIMELOCK_ADMIN_ROLE,
};
use dusk_contract_standards::proxy::{
    StateStore, UpgradeActivated, UpgradeAdmin, UpgradeCancelled,
    UpgradePrepared, UpgradeRolledBack,
};
use dusk_core::abi::ContractId;

fn p(byte: u8) -> Principal {
    Principal::phoenix([byte; 32])
}

fn c(byte: u8) -> ContractId {
    ContractId::from_bytes([byte; 32])
}

fn contract_principal(byte: u8) -> Principal {
    Principal::contract(c(byte))
}

fn assert_panics<R>(f: impl FnOnce() -> R) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}

fn upgrade_snapshot(
    admin: &UpgradeAdmin,
) -> (ContractId, Option<(ContractId, u64, Vec<u8>)>, u64) {
    (
        admin.implementation(),
        admin.pending().map(|pending| {
            (
                pending.implementation,
                pending.eta,
                pending.migrate_data.clone(),
            )
        }),
        admin.rollback_deadline(),
    )
}

#[test]
fn upgrade_admin_lifecycle_and_failure_atomicity_are_pinned() {
    let admin = p(1);
    let outsider = p(2);
    let implementation_a = c(10);
    let implementation_b = c(11);
    let implementation_c = c(12);

    assert_panics(|| UpgradeAdmin::new(p(0), implementation_a, 0, 0));
    assert_panics(|| UpgradeAdmin::new(admin, c(0), 0, 0));

    let mut upgrades = UpgradeAdmin::new(admin, implementation_a, 5, 10);
    assert_eq!(upgrades.admin(), admin);
    assert_eq!(upgrades.implementation(), implementation_a);
    assert_eq!(upgrades.rollback_deadline(), 0);

    assert_panics(|| {
        upgrades.prepare(outsider, implementation_b, 100, vec![1, 2, 3]);
    });
    assert_eq!(upgrade_snapshot(&upgrades), (implementation_a, None, 0));

    assert_eq!(
        upgrades.prepare(admin, implementation_b, 100, vec![1, 2, 3]),
        UpgradePrepared {
            implementation: implementation_b,
            eta: 105,
        }
    );
    let pending_snapshot = upgrade_snapshot(&upgrades);
    assert_panics(|| {
        upgrades.activate(admin, 104);
    });
    assert_eq!(upgrade_snapshot(&upgrades), pending_snapshot);

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
    assert_eq!(upgrades.pending(), None);

    assert_panics(|| upgrades.rollback(outsider, 110));
    assert_eq!(upgrades.implementation(), implementation_b);
    assert_eq!(
        upgrades.rollback_with_event(admin, 110),
        UpgradeRolledBack {
            from_implementation: implementation_b,
            restored_implementation: implementation_a,
        }
    );
    assert_eq!(upgrades.implementation(), implementation_a);
    assert_eq!(upgrades.rollback_deadline(), 0);

    upgrades.prepare(admin, implementation_b, 200, vec![]);
    assert_eq!(
        upgrades.cancel_pending(admin),
        UpgradeCancelled {
            implementation: implementation_b,
        }
    );
    assert_eq!(upgrades.pending(), None);
    assert_panics(|| upgrades.activate(admin, 205));

    upgrades.prepare(admin, implementation_b, 300, vec![]);
    upgrades.activate(admin, 305);
    assert_panics(|| upgrades.rollback(admin, 316));
    assert_eq!(upgrades.implementation(), implementation_b);
    assert_panics(|| upgrades.finalize_rollback_window(admin, 314));
    assert_eq!(upgrades.rollback_deadline(), 315);
    upgrades.finalize_rollback_window(admin, 315);
    assert_eq!(upgrades.rollback_deadline(), 0);

    upgrades.prepare(admin, implementation_c, 400, vec![9]);
    assert_eq!(upgrades.pending().unwrap().implementation, implementation_c);
    upgrades.prepare(admin, implementation_b, 401, vec![8]);
    assert_eq!(upgrades.pending().unwrap().implementation, implementation_b);
}

#[test]
fn upgrade_admin_overflow_paths_preserve_state() {
    let admin = p(1);
    let implementation_a = c(10);
    let implementation_b = c(11);

    let mut delay_overflow = UpgradeAdmin::new(admin, implementation_a, 1, 0);
    assert_panics(|| {
        delay_overflow.prepare(admin, implementation_b, u64::MAX, vec![]);
    });
    assert_eq!(
        upgrade_snapshot(&delay_overflow),
        (implementation_a, None, 0)
    );

    let mut rollback_overflow =
        UpgradeAdmin::new(admin, implementation_a, 0, 1);
    rollback_overflow.prepare(admin, implementation_b, u64::MAX, vec![7]);
    let before = upgrade_snapshot(&rollback_overflow);
    assert_panics(|| {
        rollback_overflow.activate(admin, u64::MAX);
    });
    assert_eq!(upgrade_snapshot(&rollback_overflow), before);
}

#[test]
fn state_store_keeps_plain_and_namespaced_state_separate() {
    let key = [1u8; 32];
    let word = [2u8; 32];
    let namespace_a = [3u8; 32];
    let namespace_b = [4u8; 32];
    let namespaced_word = [5u8; 32];

    let mut store = StateStore::new();
    assert_eq!(store.get_word(key), [0u8; 32]);
    assert_eq!(store.get_bytes(key), Vec::<u8>::new());
    assert_eq!(store.get_namespaced_word(namespace_a, key), [0u8; 32]);

    store.set_word(key, word);
    store.set_bytes(key, vec![1, 2, 3]);
    store.set_namespaced_word(namespace_a, key, namespaced_word);
    store.set_namespaced_bytes(namespace_a, key, vec![4, 5, 6]);

    assert_eq!(store.get_word(key), word);
    assert_eq!(store.get_bytes(key), vec![1, 2, 3]);
    assert_eq!(store.get_namespaced_word(namespace_a, key), namespaced_word);
    assert_eq!(store.get_namespaced_word(namespace_b, key), [0u8; 32]);
    assert_eq!(store.get_namespaced_bytes(namespace_a, key), vec![4, 5, 6]);
    assert_eq!(
        store.get_namespaced_bytes(namespace_b, key),
        Vec::<u8>::new()
    );

    store.delete_namespaced(namespace_a, key);
    assert_eq!(store.get_namespaced_word(namespace_a, key), [0u8; 32]);
    assert_eq!(
        store.get_namespaced_bytes(namespace_a, key),
        Vec::<u8>::new()
    );
    assert_eq!(store.get_word(key), word);
    assert_eq!(store.get_bytes(key), vec![1, 2, 3]);

    store.delete(key);
    assert_eq!(store.get_word(key), [0u8; 32]);
    assert_eq!(store.get_bytes(key), Vec::<u8>::new());
}

#[test]
fn timelock_scheduler_rejects_invalid_sequences_without_payload_loss() {
    let id = [1u8; 32];
    let other = [2u8; 32];
    let mut timelock = Timelock::new(5);

    assert_eq!(timelock.schedule(id, 10, vec![1, 2, 3]), 15);
    assert!(!timelock.is_ready(id, 14));
    assert!(timelock.is_ready(id, 15));
    assert_panics(|| timelock.schedule(id, 11, vec![]));
    assert_eq!(timelock.get(id).unwrap().payload, vec![1, 2, 3]);

    assert_panics(|| timelock.execute(id, 14));
    assert_eq!(timelock.get(id).unwrap().payload, vec![1, 2, 3]);
    assert_eq!(timelock.execute(id, 15), vec![1, 2, 3]);
    assert!(!timelock.is_ready(id, 16));
    assert_panics(|| timelock.execute(id, 16));
    assert_panics(|| timelock.cancel(id));

    timelock.schedule(other, 20, vec![9]);
    timelock.cancel(other);
    assert!(timelock.get(other).is_none());

    let mut overflow = Timelock::new(1);
    assert_panics(|| overflow.schedule(id, u64::MAX, vec![]));
    assert!(overflow.get(id).is_none());
}

#[test]
fn timelock_controller_gates_roles_and_self_governed_delay_change() {
    let self_principal = contract_principal(1);
    let admin = contract_principal(2);
    let proposer = contract_principal(3);
    let executor = contract_principal(4);
    let canceller = contract_principal(5);
    let outsider = contract_principal(6);
    let op = [7u8; 32];

    assert_panics(|| TimelockController::new(p(0), admin, 1));
    assert_panics(|| TimelockController::new(self_principal, p(0), 1));

    let mut controller = TimelockController::new(self_principal, admin, 5);
    assert_eq!(controller.self_principal(), self_principal);
    assert!(controller.has_role(TIMELOCK_ADMIN_ROLE, admin));
    assert!(controller.has_role(PROPOSER_ROLE, admin));
    assert!(controller.has_role(EXECUTOR_ROLE, admin));
    assert!(controller.has_role(CANCELLER_ROLE, admin));

    let mut authorizations = AuthorizationManager::new();
    let admin_auth = controller.access().authorize_role(
        dusk_contract_standards::access::DEFAULT_ADMIN_ROLE,
        &mut authorizations,
        CallContext::from_principal(admin),
        None,
        0,
    );
    controller.grant_role(admin_auth, PROPOSER_ROLE, proposer);
    let admin_auth = controller.access().authorize_role(
        dusk_contract_standards::access::DEFAULT_ADMIN_ROLE,
        &mut authorizations,
        CallContext::from_principal(admin),
        None,
        0,
    );
    controller.grant_role(admin_auth, EXECUTOR_ROLE, executor);
    let admin_auth = controller.access().authorize_role(
        dusk_contract_standards::access::DEFAULT_ADMIN_ROLE,
        &mut authorizations,
        CallContext::from_principal(admin),
        None,
        0,
    );
    controller.grant_role(admin_auth, CANCELLER_ROLE, canceller);

    assert_panics(|| controller.schedule(outsider, op, 10, vec![1]));
    assert_eq!(controller.schedule(proposer, op, 10, vec![1]), 15);
    assert_panics(|| controller.execute(executor, op, 14));
    assert_eq!(controller.execute(executor, op, 15), vec![1]);

    let cancel_id = [8u8; 32];
    controller.schedule(proposer, cancel_id, 20, vec![2]);
    assert_panics(|| controller.cancel(outsider, cancel_id));
    controller.cancel(canceller, cancel_id);
    assert!(controller.get(cancel_id).is_none());

    assert_panics(|| controller.set_min_delay(admin, 9));
    assert_eq!(controller.timelock().min_delay(), 5);
    let delay_id = [9u8; 32];
    assert_eq!(
        controller.schedule_min_delay_change(proposer, delay_id, 30, 9),
        35
    );
    assert_panics(|| {
        controller.execute_min_delay_change(executor, delay_id, 34)
    });
    assert_eq!(controller.timelock().min_delay(), 5);
    assert_eq!(
        controller.execute_min_delay_change(executor, delay_id, 35),
        9
    );
    assert_eq!(controller.timelock().min_delay(), 9);
}

#[cfg(feature = "forge")]
#[test]
fn proxy_event_topics_are_pinned() {
    use dusk_contract_standards::proxy::{
        RollbackFinalized, UpgradeActivated, UpgradeCancelled, UpgradePrepared,
        UpgradeRolledBack, ROLLBACK_FINALIZED_TOPIC, UPGRADE_ACTIVATED_TOPIC,
        UPGRADE_CANCELLED_TOPIC, UPGRADE_PREPARED_TOPIC,
        UPGRADE_ROLLED_BACK_TOPIC,
    };
    use dusk_forge::ContractEvent;

    assert_eq!(UpgradePrepared::TOPICS, &[UPGRADE_PREPARED_TOPIC]);
    assert_eq!(UpgradeActivated::TOPICS, &[UPGRADE_ACTIVATED_TOPIC]);
    assert_eq!(UpgradeCancelled::TOPICS, &[UPGRADE_CANCELLED_TOPIC]);
    assert_eq!(UpgradeRolledBack::TOPICS, &[UPGRADE_ROLLED_BACK_TOPIC]);
    assert_eq!(RollbackFinalized::TOPICS, &[ROLLBACK_FINALIZED_TOPIC]);
}
