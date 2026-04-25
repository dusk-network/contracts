//! Dusk-native proxy/state-store example.

#![no_std]
#![cfg(target_family = "wasm")]

extern crate alloc;
extern crate self as proxy_counter_types;

use alloc::vec::Vec;

use bytecheck::CheckBytes;
use dusk_contract_standards::auth::SignedAuthorization;
use dusk_contract_standards::core::{NonceDomain, Principal};
use dusk_core::abi::ContractId;
use rkyv::{Archive, Deserialize, Serialize};

pub const PROXY_ADMIN_DOMAIN: NonceDomain = [31u8; 32];
pub const SET_VALUE_ACTION: [u8; 32] = [32u8; 32];
pub const PREPARE_UPGRADE_ACTION: [u8; 32] = [33u8; 32];
pub const ACTIVATE_UPGRADE_ACTION: [u8; 32] = [34u8; 32];
pub const CANCEL_UPGRADE_ACTION: [u8; 32] = [35u8; 32];
pub const ROLLBACK_ACTION: [u8; 32] = [36u8; 32];
pub const FINALIZE_ROLLBACK_ACTION: [u8; 32] = [37u8; 32];
pub const VALUE_CHANGED_TOPIC: &str = "proxy_counter/value_changed";

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    pub admin: Principal,
    pub implementation: ContractId,
    pub upgrade_delay: u64,
    pub rollback_window: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrepareUpgrade {
    pub implementation: ContractId,
    pub migrate_data: Vec<u8>,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetValue {
    pub value: u64,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct AdminCall {
    pub authorization: Option<SignedAuthorization>,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ValueChanged {
    pub previous: u64,
    pub value: u64,
    pub sender: Option<Principal>,
}

#[dusk_forge::contract]
mod proxy_counter {
    use alloc::vec::Vec;

    use dusk_contract_standards::auth::{
        ActionEnvelope, AuthorizationManager, SignedAuthorization,
    };
    use dusk_contract_standards::core::{
        error, CallContext, NonceQuery, Principal,
    };
    use dusk_contract_standards::proxy::{
        RollbackFinalized, StateStore, UpgradeActivated, UpgradeAdmin,
        UpgradeCancelled, UpgradePrepared, UpgradeRolledBack,
        ROLLBACK_FINALIZED_TOPIC, UPGRADE_ACTIVATED_TOPIC,
        UPGRADE_CANCELLED_TOPIC, UPGRADE_PREPARED_TOPIC,
        UPGRADE_ROLLED_BACK_TOPIC,
    };
    use dusk_core::abi::{self, ContractId};
    use proxy_counter_types::{
        AdminCall, Init, PrepareUpgrade, SetValue, ValueChanged,
        ACTIVATE_UPGRADE_ACTION, CANCEL_UPGRADE_ACTION,
        FINALIZE_ROLLBACK_ACTION, PREPARE_UPGRADE_ACTION, PROXY_ADMIN_DOMAIN,
        ROLLBACK_ACTION, SET_VALUE_ACTION, VALUE_CHANGED_TOPIC,
    };

    const COUNTER_KEY: [u8; 32] = [7u8; 32];

    pub struct ProxyCounter {
        store: StateStore,
        admin: Option<UpgradeAdmin>,
        authorizations: AuthorizationManager,
    }

    impl ProxyCounter {
        pub const fn new() -> Self {
            Self {
                store: StateStore::new(),
                admin: None,
                authorizations: AuthorizationManager::new(),
            }
        }

        #[contract(no_event)]
        pub fn init(&mut self, args: Init) {
            if self.admin.is_some() {
                panic!("{}", error::ALREADY_INITIALIZED);
            }
            self.admin = Some(UpgradeAdmin::new(
                args.admin,
                args.implementation,
                args.upgrade_delay,
                args.rollback_window,
            ));
        }

        pub fn implementation(&self) -> ContractId {
            self.admin().implementation()
        }

        pub fn rollback_deadline(&self) -> u64 {
            self.admin().rollback_deadline()
        }

        pub fn nonce(&self, args: NonceQuery) -> u64 {
            self.authorizations.nonce(args.principal, args.domain)
        }

        pub fn value(&self) -> u64 {
            u64::from_be_bytes(
                self.store.get_word(COUNTER_KEY)[24..32].try_into().unwrap(),
            )
        }

        #[contract(emits = [(VALUE_CHANGED_TOPIC, ValueChanged)])]
        pub fn increment(&mut self) {
            let previous = self.value();
            let next = previous.checked_add(1).expect(error::OVERFLOW);
            self.write_value(next);
            Self::emit_value_changed(
                previous,
                next,
                CallContext::current().principal,
            );
        }

        #[contract(emits = [(VALUE_CHANGED_TOPIC, ValueChanged)])]
        pub fn set_value(&mut self, args: SetValue) {
            let previous = self.value();
            let caller = self.authorize_admin_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    PROXY_ADMIN_DOMAIN,
                    SET_VALUE_ACTION,
                    value_payload_hash(args.value),
                ),
            );
            self.write_value(args.value);
            Self::emit_value_changed(previous, args.value, Some(caller));
        }

        #[contract(emits = [(UPGRADE_PREPARED_TOPIC, UpgradePrepared)])]
        pub fn prepare_upgrade(&mut self, args: PrepareUpgrade) {
            let caller = self.authorize_admin_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    PROXY_ADMIN_DOMAIN,
                    PREPARE_UPGRADE_ACTION,
                    prepare_payload_hash(
                        args.implementation,
                        &args.migrate_data,
                    ),
                ),
            );
            let event = self.admin_mut().prepare(
                caller,
                args.implementation,
                now(),
                args.migrate_data,
            );
            Self::emit_upgrade_prepared(event);
        }

        #[contract(emits = [(UPGRADE_ACTIVATED_TOPIC, UpgradeActivated)])]
        pub fn activate_upgrade(&mut self, args: AdminCall) -> Vec<u8> {
            let caller = self.authorize_admin_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    PROXY_ADMIN_DOMAIN,
                    ACTIVATE_UPGRADE_ACTION,
                    empty_payload_hash(b"proxy.activate_upgrade"),
                ),
            );
            let (migrate_data, event) =
                self.admin_mut().activate_with_event(caller, now());
            Self::emit_upgrade_activated(event);
            migrate_data
        }

        #[contract(emits = [(UPGRADE_CANCELLED_TOPIC, UpgradeCancelled)])]
        pub fn cancel_pending_upgrade(&mut self, args: AdminCall) {
            let caller = self.authorize_admin_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    PROXY_ADMIN_DOMAIN,
                    CANCEL_UPGRADE_ACTION,
                    empty_payload_hash(b"proxy.cancel_upgrade"),
                ),
            );
            let event = self.admin_mut().cancel_pending(caller);
            Self::emit_upgrade_cancelled(event);
        }

        #[contract(emits = [(UPGRADE_ROLLED_BACK_TOPIC, UpgradeRolledBack)])]
        pub fn rollback(&mut self, args: AdminCall) {
            let caller = self.authorize_admin_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    PROXY_ADMIN_DOMAIN,
                    ROLLBACK_ACTION,
                    empty_payload_hash(b"proxy.rollback"),
                ),
            );
            let event = self.admin_mut().rollback_with_event(caller, now());
            Self::emit_upgrade_rolled_back(event);
        }

        #[contract(emits = [(ROLLBACK_FINALIZED_TOPIC, RollbackFinalized)])]
        pub fn finalize_rollback_window(&mut self, args: AdminCall) {
            let caller = self.authorize_admin_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    PROXY_ADMIN_DOMAIN,
                    FINALIZE_ROLLBACK_ACTION,
                    empty_payload_hash(b"proxy.finalize_rollback"),
                ),
            );
            let event = self
                .admin_mut()
                .finalize_rollback_window_with_event(caller, now());
            Self::emit_rollback_finalized(event);
        }

        fn write_value(&mut self, value: u64) {
            let mut word = [0u8; 32];
            word[24..32].copy_from_slice(&value.to_be_bytes());
            self.store.set_word(COUNTER_KEY, word);
        }

        fn authorize_admin_action(
            &mut self,
            authorization: Option<&SignedAuthorization>,
            envelope: ActionEnvelope,
        ) -> Principal {
            let admin = self.admin().admin();
            self.authorizations.authorize_principal_action(
                admin,
                CallContext::current(),
                authorization,
                envelope,
                now(),
            )
        }

        fn emit_upgrade_prepared(event: UpgradePrepared) {
            abi::emit(
                UPGRADE_PREPARED_TOPIC,
                UpgradePrepared {
                    implementation: event.implementation,
                    eta: event.eta,
                },
            );
        }

        fn emit_upgrade_activated(event: UpgradeActivated) {
            abi::emit(
                UPGRADE_ACTIVATED_TOPIC,
                UpgradeActivated {
                    previous_implementation: event.previous_implementation,
                    implementation: event.implementation,
                    rollback_deadline: event.rollback_deadline,
                },
            );
        }

        fn emit_upgrade_cancelled(event: UpgradeCancelled) {
            abi::emit(
                UPGRADE_CANCELLED_TOPIC,
                UpgradeCancelled {
                    implementation: event.implementation,
                },
            );
        }

        fn emit_upgrade_rolled_back(event: UpgradeRolledBack) {
            abi::emit(
                UPGRADE_ROLLED_BACK_TOPIC,
                UpgradeRolledBack {
                    from_implementation: event.from_implementation,
                    restored_implementation: event.restored_implementation,
                },
            );
        }

        fn emit_rollback_finalized(event: RollbackFinalized) {
            abi::emit(
                ROLLBACK_FINALIZED_TOPIC,
                RollbackFinalized {
                    implementation: event.implementation,
                },
            );
        }

        fn emit_value_changed(
            previous: u64,
            value: u64,
            sender: Option<Principal>,
        ) {
            abi::emit(
                VALUE_CHANGED_TOPIC,
                ValueChanged {
                    previous,
                    value,
                    sender,
                },
            );
        }

        fn admin(&self) -> &UpgradeAdmin {
            self.admin
                .as_ref()
                .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED))
        }

        fn admin_mut(&mut self) -> &mut UpgradeAdmin {
            self.admin
                .as_mut()
                .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED))
        }
    }

    impl Default for ProxyCounter {
        fn default() -> Self {
            Self::new()
        }
    }

    fn now() -> u64 {
        abi::block_height()
    }

    fn empty_payload_hash(tag: &[u8]) -> [u8; 32] {
        abi::keccak256(Vec::from(tag))
    }

    fn value_payload_hash(value: u64) -> [u8; 32] {
        let mut bytes = Vec::from(&b"proxy.value"[..]);
        bytes.extend_from_slice(&value.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn prepare_payload_hash(
        implementation: ContractId,
        migrate_data: &[u8],
    ) -> [u8; 32] {
        let mut bytes = Vec::from(&b"proxy.prepare"[..]);
        bytes.extend_from_slice(&implementation.to_bytes());
        bytes.extend_from_slice(&(migrate_data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(migrate_data);
        abi::keccak256(bytes)
    }
}
