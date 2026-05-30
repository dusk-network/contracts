// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(target_family = "wasm", no_std)]

#[cfg(target_family = "wasm")]
extern crate alloc;

#[cfg(target_family = "wasm")]
#[dusk_forge::contract(events = [
    PrivateMintEvent,
    PrivateTransferEvent,
    PrivateBurnEvent,
    PausedEvent,
    UnpausedEvent
])]
mod drc20_phoenix_reference {
    use alloc::string::String;
    use alloc::vec::Vec;

    use dusk_contract_standards::token::drc20_phoenix::{
        AdminId, Drc20Phoenix, ExistingNullifiersQuery, Init, OpeningQuery,
        PausedEvent, PrivateAssetLeaf, PrivateAssetNote, PrivateAssetProof,
        PrivateAssetPublicInputBuilder, PrivateAssetPublicInputs, PrivateBurn,
        PrivateBurnEvent, PrivateMint, PrivateMintEvent, PrivateNoteOpening,
        PrivateTransfer, PrivateTransferEvent, RootExistsQuery,
        SyncNullifiersQuery, SyncQuery, TokenMetadata, UnpausedEvent,
        PAUSED_TOPIC, PRIVATE_BURN_TOPIC, PRIVATE_MINT_TOPIC,
        PRIVATE_TRANSFER_TOPIC, UNPAUSED_TOPIC,
    };
    use dusk_core::abi;
    use dusk_core::abi::ContractId;
    use dusk_core::BlsScalar;

    /// Forge reference contract for the DRC20Phoenix primitive.
    pub struct Drc20PhoenixReference {
        token: Option<Drc20Phoenix>,
    }

    impl Drc20PhoenixReference {
        /// Creates an uninitialized reference contract.
        pub const fn new() -> Self {
            Self { token: None }
        }

        /// Initializes the private token.
        pub fn init(&mut self, init: Init) {
            if self.token.is_some() {
                panic!("DRC20PhoenixReference: already initialized");
            }
            let mut token = Drc20Phoenix::new();
            token.init(init);
            self.token = Some(token);
        }

        /// Returns token metadata.
        pub fn metadata(&self) -> TokenMetadata {
            self.token().metadata()
        }

        /// Returns token name.
        pub fn name(&self) -> String {
            self.token().name()
        }

        /// Returns token symbol.
        pub fn symbol(&self) -> String {
            self.token().symbol()
        }

        /// Returns token decimals.
        pub fn decimals(&self) -> u8 {
            self.token().decimals()
        }

        /// Returns standard version.
        pub fn version(&self) -> u32 {
            self.token().version()
        }

        /// Returns asset id.
        pub fn asset_id(&self) -> BlsScalar {
            self.token().asset_id()
        }

        /// Returns current root.
        pub fn root(&self) -> BlsScalar {
            self.token().root()
        }

        /// Checks retained-root membership.
        pub fn root_exists(&self, query: RootExistsQuery) -> bool {
            self.token().root_exists(query.root)
        }

        /// Returns a note opening by append position.
        pub fn opening(
            &self,
            query: OpeningQuery,
        ) -> Option<PrivateNoteOpening> {
            self.token().opening(query.position)
        }

        /// Returns note count.
        pub fn num_notes(&self) -> u64 {
            self.token().num_notes()
        }

        /// Filters already-spent nullifiers.
        pub fn existing_nullifiers(
            &self,
            query: ExistingNullifiersQuery,
        ) -> Vec<BlsScalar> {
            self.token().existing_nullifiers(query.nullifiers)
        }

        /// Syncs note leaves in append order.
        pub fn sync(&self, query: SyncQuery) -> Vec<PrivateAssetLeaf> {
            self.token().sync(query.from, query.count_limit)
        }

        /// Syncs nullifiers in append order.
        pub fn sync_nullifiers(
            &self,
            query: SyncNullifiersQuery,
        ) -> Vec<BlsScalar> {
            self.token().sync_nullifiers(query.from, query.count_limit)
        }

        /// Returns public minted supply.
        pub fn minted_supply(&self) -> u128 {
            self.token().minted_supply()
        }

        /// Returns public burned supply.
        pub fn burned_supply(&self) -> u128 {
            self.token().burned_supply()
        }

        /// Returns public net supply.
        pub fn net_supply(&self) -> u128 {
            self.token().net_supply()
        }

        /// Returns optional mint cap.
        pub fn cap(&self) -> Option<u128> {
            self.token().cap()
        }

        /// Returns pause state.
        pub fn paused(&self) -> bool {
            self.token().paused()
        }

        /// Returns verifier data hash.
        pub fn verifier_data_hash(&self) -> BlsScalar {
            self.token().verifier_data_hash()
        }

        /// Builds proof public inputs for client/prover integrations.
        pub fn build_public_inputs(
            &self,
            chain_id: u8,
            contract_id: ContractId,
            asset_id: BlsScalar,
            mode: dusk_contract_standards::token::drc20_phoenix::PrivateAssetCircuitMode,
            root: BlsScalar,
            nullifiers: Vec<BlsScalar>,
            outputs: Vec<PrivateAssetNote>,
            public_mint_amount: u128,
            public_burn_amount: u128,
            memo_hash: BlsScalar,
        ) -> PrivateAssetPublicInputs {
            self.token()
                .build_public_inputs(PrivateAssetPublicInputBuilder {
                    chain_id,
                    contract_id,
                    asset_id,
                    mode,
                    root,
                    nullifiers: &nullifiers,
                    outputs: &outputs,
                    public_mint_amount,
                    public_burn_amount,
                    memo_hash,
                })
        }

        /// Mints private notes.
        pub fn mint_private(&mut self, mint: PrivateMint) -> PrivateMintEvent {
            let event = self.token_mut().mint_private(mint);
            abi::emit(PRIVATE_MINT_TOPIC, event.clone());
            event
        }

        /// Transfers private notes.
        pub fn transfer_private(
            &mut self,
            transfer: PrivateTransfer,
        ) -> PrivateTransferEvent {
            let event = self.token_mut().transfer_private(transfer);
            abi::emit(PRIVATE_TRANSFER_TOPIC, event.clone());
            event
        }

        /// Burns private notes.
        pub fn burn_private(&mut self, burn: PrivateBurn) -> PrivateBurnEvent {
            let event = self.token_mut().burn_private(burn);
            abi::emit(PRIVATE_BURN_TOPIC, event.clone());
            event
        }

        /// Pauses mint, transfer, and burn.
        pub fn pause(&mut self, caller: AdminId) -> PausedEvent {
            let event = self.token_mut().pause(caller);
            abi::emit(PAUSED_TOPIC, event);
            event
        }

        /// Unpauses mint, transfer, and burn.
        pub fn unpause(&mut self, caller: AdminId) -> UnpausedEvent {
            let event = self.token_mut().unpause(caller);
            abi::emit(UNPAUSED_TOPIC, event);
            event
        }

        /// Explicit proof passthrough used by data-driver clients.
        pub fn proof_public_inputs(
            &self,
            proof: PrivateAssetProof,
        ) -> PrivateAssetPublicInputs {
            proof.public_inputs
        }

        fn token(&self) -> &Drc20Phoenix {
            self.token
                .as_ref()
                .expect("DRC20PhoenixReference: not initialized")
        }

        fn token_mut(&mut self) -> &mut Drc20Phoenix {
            self.token
                .as_mut()
                .expect("DRC20PhoenixReference: not initialized")
        }
    }
}
