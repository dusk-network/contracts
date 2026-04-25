//! Example DRC721 composed from reusable Dusk contract standards modules.

#![no_std]
#![cfg(target_family = "wasm")]

extern crate alloc;
extern crate self as drc721_collection_types;

use bytecheck::CheckBytes;
use dusk_contract_standards::auth::SignedAuthorization;
use dusk_contract_standards::core::{NonceDomain, Principal};
use dusk_contract_standards::token::drc721::{Init as TokenInit, RoyaltyInfo};
use rkyv::{Archive, Deserialize, Serialize};

pub const NFT_ADMIN_DOMAIN: NonceDomain = [21u8; 32];
pub const MINT_ACTION: [u8; 32] = [22u8; 32];
pub const PAUSE_ACTION: [u8; 32] = [23u8; 32];
pub const UNPAUSE_ACTION: [u8; 32] = [24u8; 32];
pub const SET_DEFAULT_ROYALTY_ACTION: [u8; 32] = [25u8; 32];
pub const CLEAR_DEFAULT_ROYALTY_ACTION: [u8; 32] = [26u8; 32];
pub const SET_TOKEN_ROYALTY_ACTION: [u8; 32] = [27u8; 32];
pub const CLEAR_TOKEN_ROYALTY_ACTION: [u8; 32] = [28u8; 32];

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    pub owner: Principal,
    pub token: TokenInit,
    pub default_royalty: Option<RoyaltyInfo>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MintCall {
    pub to: Principal,
    pub token_id: u64,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct AdminCall {
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetDefaultRoyaltyCall {
    pub info: RoyaltyInfo,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetTokenRoyaltyCall {
    pub token_id: u64,
    pub info: RoyaltyInfo,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ClearTokenRoyaltyCall {
    pub token_id: u64,
    pub authorization: Option<SignedAuthorization>,
}

#[dusk_forge::contract]
mod drc721_collection {
    use alloc::collections::BTreeSet;
    use alloc::string::String;
    use alloc::vec::Vec;

    use drc721_collection_types::{
        AdminCall, ClearTokenRoyaltyCall, Init, MintCall,
        SetDefaultRoyaltyCall, SetTokenRoyaltyCall,
        CLEAR_DEFAULT_ROYALTY_ACTION, CLEAR_TOKEN_ROYALTY_ACTION, MINT_ACTION,
        NFT_ADMIN_DOMAIN, PAUSE_ACTION, SET_DEFAULT_ROYALTY_ACTION,
        SET_TOKEN_ROYALTY_ACTION, UNPAUSE_ACTION,
    };
    use dusk_contract_standards::access::events::{
        Paused, Unpaused, PAUSED_TOPIC, UNPAUSED_TOPIC,
    };
    use dusk_contract_standards::access::{Ownable, Pausable};
    use dusk_contract_standards::auth::{
        ActionEnvelope, AuthorizationManager, SignedAuthorization,
    };
    use dusk_contract_standards::core::{
        error, CallContext, NonceQuery, Principal,
    };
    use dusk_contract_standards::security::ReentrancyGuard;
    use dusk_contract_standards::token::drc721::events::{
        Approval as Drc721Approval, ApprovalForAll as Drc721ApprovalForAll,
        DefaultRoyaltyCleared, DefaultRoyaltySet, TokenRoyaltyCleared,
        TokenRoyaltySet, Transfer as Drc721Transfer, APPROVAL_FOR_ALL_TOPIC,
        APPROVAL_TOPIC, DEFAULT_ROYALTY_CLEARED_TOPIC,
        DEFAULT_ROYALTY_SET_TOPIC, TOKEN_ROYALTY_CLEARED_TOPIC,
        TOKEN_ROYALTY_SET_TOPIC, TRANSFER_TOPIC,
    };
    use dusk_contract_standards::token::drc721::{
        ApproveCall, BalanceOf, Drc721, GetApproved, IsApprovedForAll, OwnerOf,
        RoyaltyInfo, RoyaltyQuery, RoyaltyQuote, RoyaltyRegistry,
        SetApprovalForAllCall, TokenByIndex, TokenOfOwnerByIndex, TokenUri,
        TokensOf, TransferFromCall,
    };
    use dusk_core::abi;

    pub struct Drc721Collection {
        token: Drc721,
        ownable: Ownable,
        authorizations: AuthorizationManager,
        pausable: Pausable,
        guard: ReentrancyGuard,
        royalties: RoyaltyRegistry,
    }

    impl Drc721Collection {
        pub const fn new() -> Self {
            Self {
                token: Drc721::new(),
                ownable: Ownable::new(),
                authorizations: AuthorizationManager::new(),
                pausable: Pausable::new(),
                guard: ReentrancyGuard::new(),
                royalties: RoyaltyRegistry::new(),
            }
        }

        #[contract(emits = [(TRANSFER_TOPIC, Drc721Transfer)])]
        pub fn init(&mut self, args: Init) {
            if args.owner.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            let mut token_ids = BTreeSet::new();
            for token in &args.token.initial_tokens {
                if token.account.is_zero() {
                    panic!("{}", error::ZERO_PRINCIPAL);
                }
                if !token_ids.insert(token.token_id) {
                    panic!("DRC721: token already minted");
                }
            }
            let mut royalties = RoyaltyRegistry::new();
            if let Some(info) = args.default_royalty {
                royalties.set_default_royalty(info);
            }

            self.ownable.init(args.owner);
            for event in self.token.init(args.token) {
                Self::emit_transfer(event);
            }
            self.royalties = royalties;
        }

        pub fn name(&self) -> String {
            self.token.name()
        }

        pub fn symbol(&self) -> String {
            self.token.symbol()
        }

        pub fn base_uri(&self) -> String {
            self.token.base_uri()
        }

        pub fn token_uri(&self, args: TokenUri) -> String {
            self.token.token_uri(args)
        }

        pub fn token_by_index(&self, args: TokenByIndex) -> u64 {
            self.token.token_by_index(args)
        }

        pub fn token_of_owner_by_index(
            &self,
            args: TokenOfOwnerByIndex,
        ) -> u64 {
            self.token.token_of_owner_by_index(args)
        }

        pub fn tokens_of(&self, args: TokensOf) -> alloc::vec::Vec<u64> {
            self.token.tokens_of(args)
        }

        pub fn total_supply(&self) -> u64 {
            self.token.total_supply()
        }

        pub fn balance_of(&self, args: BalanceOf) -> u64 {
            self.token.balance_of(args)
        }

        pub fn owner_of(&self, args: OwnerOf) -> Principal {
            self.token.owner_of(args)
        }

        pub fn get_approved(&self, args: GetApproved) -> Principal {
            self.token.get_approved(args)
        }

        pub fn is_approved_for_all(&self, args: IsApprovedForAll) -> bool {
            self.token.is_approved_for_all(args)
        }

        pub fn nonce(&self, args: NonceQuery) -> u64 {
            self.authorizations.nonce(args.principal, args.domain)
        }

        pub fn royalty_info(&self, args: RoyaltyQuery) -> RoyaltyQuote {
            self.royalties.royalty_info(args.token_id, args.sale_price)
        }

        #[contract(emits = [(APPROVAL_TOPIC, Drc721Approval)])]
        pub fn approve(&mut self, args: ApproveCall) {
            let event = self.token.approve(caller(), args);
            Self::emit_approval(event);
        }

        #[contract(emits = [(APPROVAL_FOR_ALL_TOPIC, Drc721ApprovalForAll)])]
        pub fn set_approval_for_all(&mut self, args: SetApprovalForAllCall) {
            let event = self.token.set_approval_for_all(caller(), args);
            Self::emit_approval_for_all(event);
        }

        #[contract(emits = [(TRANSFER_TOPIC, Drc721Transfer)])]
        pub fn transfer_from(&mut self, args: TransferFromCall) {
            self.pausable.assert_not_paused();
            let caller = caller();
            let event = {
                let guard = &mut self.guard;
                let token = &mut self.token;
                guard.run(|| token.transfer_from(caller, args))
            };
            Self::emit_transfer(event);
        }

        #[contract(emits = [(TRANSFER_TOPIC, Drc721Transfer)])]
        pub fn mint(&mut self, args: MintCall) {
            self.pausable.assert_not_paused();
            self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    MINT_ACTION,
                    mint_payload_hash(args.to, args.token_id),
                ),
            );
            let event = self.token.mint(args.to, args.token_id);
            Self::emit_transfer(event);
        }

        #[contract(emits = [(TRANSFER_TOPIC, Drc721Transfer)])]
        pub fn burn(&mut self, token_id: u64) {
            self.pausable.assert_not_paused();
            let event = self.token.burn(caller(), token_id);
            Self::emit_transfer(event);
        }

        #[contract(emits = [(PAUSED_TOPIC, Paused)])]
        pub fn pause(&mut self, args: AdminCall) {
            let caller = self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    PAUSE_ACTION,
                    empty_payload_hash(b"drc721.pause"),
                ),
            );
            self.pausable.assert_not_paused();
            self.pausable.pause();
            Self::emit_paused(caller);
        }

        #[contract(emits = [(UNPAUSED_TOPIC, Unpaused)])]
        pub fn unpause(&mut self, args: AdminCall) {
            let caller = self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    UNPAUSE_ACTION,
                    empty_payload_hash(b"drc721.unpause"),
                ),
            );
            self.pausable.assert_paused();
            self.pausable.unpause();
            Self::emit_unpaused(caller);
        }

        pub fn paused(&self) -> bool {
            self.pausable.paused()
        }

        #[contract(emits = [(DEFAULT_ROYALTY_SET_TOPIC, DefaultRoyaltySet)])]
        pub fn set_default_royalty(&mut self, args: SetDefaultRoyaltyCall) {
            let caller = self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    SET_DEFAULT_ROYALTY_ACTION,
                    royalty_payload_hash(None, args.info),
                ),
            );
            self.royalties.set_default_royalty(args.info);
            Self::emit_default_royalty_set(caller, args.info);
        }

        #[contract(
            emits = [(DEFAULT_ROYALTY_CLEARED_TOPIC, DefaultRoyaltyCleared)]
        )]
        pub fn clear_default_royalty(&mut self, args: AdminCall) {
            let caller = self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    CLEAR_DEFAULT_ROYALTY_ACTION,
                    empty_payload_hash(b"drc721.clear_default_royalty"),
                ),
            );
            self.royalties.clear_default_royalty();
            Self::emit_default_royalty_cleared(caller);
        }

        #[contract(emits = [(TOKEN_ROYALTY_SET_TOPIC, TokenRoyaltySet)])]
        pub fn set_token_royalty(&mut self, args: SetTokenRoyaltyCall) {
            let caller = self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    SET_TOKEN_ROYALTY_ACTION,
                    royalty_payload_hash(Some(args.token_id), args.info),
                ),
            );
            self.royalties.set_token_royalty(args.token_id, args.info);
            Self::emit_token_royalty_set(caller, args.token_id, args.info);
        }

        #[contract(emits = [(TOKEN_ROYALTY_CLEARED_TOPIC, TokenRoyaltyCleared)])]
        pub fn clear_token_royalty(&mut self, args: ClearTokenRoyaltyCall) {
            let caller = self.authorize_owner_action(
                args.authorization.as_ref(),
                ActionEnvelope::new(
                    abi::self_id(),
                    NFT_ADMIN_DOMAIN,
                    CLEAR_TOKEN_ROYALTY_ACTION,
                    token_payload_hash(args.token_id),
                ),
            );
            self.royalties.clear_token_royalty(args.token_id);
            Self::emit_token_royalty_cleared(caller, args.token_id);
        }

        fn authorize_owner_action(
            &mut self,
            authorization: Option<&SignedAuthorization>,
            envelope: ActionEnvelope,
        ) -> Principal {
            self.ownable.authorize_owner_action(
                &mut self.authorizations,
                CallContext::current(),
                authorization,
                envelope,
                now(),
            )
        }

        fn emit_transfer(event: Drc721Transfer) {
            abi::emit(
                TRANSFER_TOPIC,
                Drc721Transfer {
                    from: event.from,
                    to: event.to,
                    token_id: event.token_id,
                },
            );
        }

        fn emit_approval(event: Drc721Approval) {
            abi::emit(
                APPROVAL_TOPIC,
                Drc721Approval {
                    owner: event.owner,
                    approved: event.approved,
                    token_id: event.token_id,
                },
            );
        }

        fn emit_approval_for_all(event: Drc721ApprovalForAll) {
            abi::emit(
                APPROVAL_FOR_ALL_TOPIC,
                Drc721ApprovalForAll {
                    owner: event.owner,
                    operator: event.operator,
                    approved: event.approved,
                },
            );
        }

        fn emit_paused(account: Principal) {
            abi::emit(PAUSED_TOPIC, Paused { account });
        }

        fn emit_unpaused(account: Principal) {
            abi::emit(UNPAUSED_TOPIC, Unpaused { account });
        }

        fn emit_default_royalty_set(operator: Principal, info: RoyaltyInfo) {
            abi::emit(
                DEFAULT_ROYALTY_SET_TOPIC,
                DefaultRoyaltySet {
                    operator,
                    receiver: info.receiver,
                    basis_points: info.basis_points,
                },
            );
        }

        fn emit_default_royalty_cleared(operator: Principal) {
            abi::emit(
                DEFAULT_ROYALTY_CLEARED_TOPIC,
                DefaultRoyaltyCleared { operator },
            );
        }

        fn emit_token_royalty_set(
            operator: Principal,
            token_id: u64,
            info: RoyaltyInfo,
        ) {
            abi::emit(
                TOKEN_ROYALTY_SET_TOPIC,
                TokenRoyaltySet {
                    operator,
                    token_id,
                    receiver: info.receiver,
                    basis_points: info.basis_points,
                },
            );
        }

        fn emit_token_royalty_cleared(operator: Principal, token_id: u64) {
            abi::emit(
                TOKEN_ROYALTY_CLEARED_TOPIC,
                TokenRoyaltyCleared { operator, token_id },
            );
        }
    }

    impl Default for Drc721Collection {
        fn default() -> Self {
            Self::new()
        }
    }

    fn caller() -> Principal {
        CallContext::current().require_principal(error::UNAUTHORIZED)
    }

    fn empty_payload_hash(tag: &[u8]) -> [u8; 32] {
        abi::keccak256(Vec::from(tag))
    }

    fn mint_payload_hash(to: Principal, token_id: u64) -> [u8; 32] {
        let mut bytes = Vec::from(&b"drc721.mint"[..]);
        push_principal(&mut bytes, to);
        bytes.extend_from_slice(&token_id.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn royalty_payload_hash(
        token_id: Option<u64>,
        info: RoyaltyInfo,
    ) -> [u8; 32] {
        let mut bytes = Vec::from(&b"drc721.royalty"[..]);
        match token_id {
            Some(token_id) => {
                bytes.push(1);
                bytes.extend_from_slice(&token_id.to_be_bytes());
            }
            None => bytes.push(0),
        }
        push_principal(&mut bytes, info.receiver);
        bytes.extend_from_slice(&info.basis_points.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn token_payload_hash(token_id: u64) -> [u8; 32] {
        let mut bytes = Vec::from(&b"drc721.token"[..]);
        bytes.extend_from_slice(&token_id.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn push_principal(bytes: &mut Vec<u8>, principal: Principal) {
        let principal = principal.to_bytes();
        bytes.extend_from_slice(&(principal.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&principal);
    }

    fn now() -> u64 {
        abi::block_height()
    }
}
