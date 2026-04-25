//! DRC721 non-fungible token primitive.

pub mod events;
pub mod royalty;
pub mod types;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};

use crate::core::{error, Principal};
use events::{Approval, ApprovalForAll, Transfer};
pub use royalty::{
    RoyaltyInfo, RoyaltyQuery, RoyaltyQuote, RoyaltyRegistry, MAX_BASIS_POINTS,
};
pub use types::{
    ApproveCall, BalanceOf, GetApproved, Init, InitToken, IsApprovedForAll,
    OwnerOf, SetApprovalForAllCall, SignedApproveCall,
    SignedSetApprovalForAllCall, TokenByIndex, TokenOfOwnerByIndex, TokenUri,
    TokensOf, TransferFromCall,
};

/// Reserved zero principal.
pub const ZERO_PRINCIPAL: Principal =
    Principal::Contract(dusk_core::abi::ContractId::from_bytes([0u8; 32]));

/// DRC721 token state and logic.
#[derive(Clone, Debug)]
pub struct Drc721 {
    initialized: bool,
    name: String,
    symbol: String,
    owners: BTreeMap<u64, Principal>,
    balances: BTreeMap<Principal, u64>,
    token_approvals: BTreeMap<u64, Principal>,
    operator_approvals: BTreeMap<(Principal, Principal), bool>,
    supply: u64,
    base_uri: String,
}

impl Drc721 {
    /// Creates empty state.
    pub const fn new() -> Self {
        Self {
            initialized: false,
            name: String::new(),
            symbol: String::new(),
            owners: BTreeMap::new(),
            balances: BTreeMap::new(),
            token_approvals: BTreeMap::new(),
            operator_approvals: BTreeMap::new(),
            supply: 0,
            base_uri: String::new(),
        }
    }

    /// Initializes token metadata and initial distribution.
    pub fn init(&mut self, args: Init) -> alloc::vec::Vec<Transfer> {
        if self.initialized {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        let mut token_ids = BTreeSet::new();
        for token in &args.initial_tokens {
            if token.account.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            if !token_ids.insert(token.token_id) {
                panic!("DRC721: token already minted");
            }
        }

        self.initialized = true;
        self.name = args.name;
        self.symbol = args.symbol;
        self.base_uri = args.base_uri;
        let mut out = alloc::vec::Vec::new();
        for token in args.initial_tokens {
            self.mint_internal(token.account, token.token_id);
            out.push(Transfer {
                from: ZERO_PRINCIPAL,
                to: token.account,
                token_id: token.token_id,
            });
        }
        out
    }

    /// Name.
    pub fn name(&self) -> String {
        self.assert_initialized();
        self.name.clone()
    }

    /// Symbol.
    pub fn symbol(&self) -> String {
        self.assert_initialized();
        self.symbol.clone()
    }

    /// Base URI.
    pub fn base_uri(&self) -> String {
        self.assert_initialized();
        self.base_uri.clone()
    }

    /// Token URI.
    pub fn token_uri(&self, args: TokenUri) -> String {
        self.assert_initialized();
        self.require_exists(args.token_id);
        if self.base_uri.is_empty() {
            return String::new();
        }
        let mut uri = self.base_uri.clone();
        uri.push_str(&args.token_id.to_string());
        uri
    }

    /// Token id by global index.
    pub fn token_by_index(&self, args: TokenByIndex) -> u64 {
        self.assert_initialized();
        self.owners
            .keys()
            .nth(args.index as usize)
            .copied()
            .unwrap_or_else(|| panic!("DRC721: global index out of bounds"))
    }

    /// Token id by owner-local index.
    pub fn token_of_owner_by_index(&self, args: TokenOfOwnerByIndex) -> u64 {
        self.assert_initialized();
        self.owners
            .iter()
            .filter_map(|(token_id, owner)| {
                if *owner == args.owner {
                    Some(*token_id)
                } else {
                    None
                }
            })
            .nth(args.index as usize)
            .unwrap_or_else(|| panic!("DRC721: owner index out of bounds"))
    }

    /// All token ids owned by an account.
    pub fn tokens_of(&self, args: TokensOf) -> alloc::vec::Vec<u64> {
        self.assert_initialized();
        self.owners
            .iter()
            .filter_map(|(token_id, owner)| {
                if *owner == args.owner {
                    Some(*token_id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Total supply.
    pub fn total_supply(&self) -> u64 {
        self.assert_initialized();
        self.supply
    }

    /// Balance of an account.
    pub fn balance_of(&self, args: BalanceOf) -> u64 {
        self.assert_initialized();
        if args.account.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.balances.get(&args.account).copied().unwrap_or(0)
    }

    /// Owner of a token.
    pub fn owner_of(&self, args: OwnerOf) -> Principal {
        self.assert_initialized();
        self.owners
            .get(&args.token_id)
            .copied()
            .unwrap_or_else(|| panic!("DRC721: token does not exist"))
    }

    /// Approved principal for a token.
    pub fn get_approved(&self, args: GetApproved) -> Principal {
        self.assert_initialized();
        self.require_exists(args.token_id);
        self.token_approvals
            .get(&args.token_id)
            .copied()
            .unwrap_or(ZERO_PRINCIPAL)
    }

    /// Operator approval.
    pub fn is_approved_for_all(&self, args: IsApprovedForAll) -> bool {
        self.assert_initialized();
        self.operator_approvals
            .get(&(args.owner, args.operator))
            .copied()
            .unwrap_or(false)
    }

    /// Approves an account for a token.
    pub fn approve(
        &mut self,
        caller: Principal,
        args: ApproveCall,
    ) -> Approval {
        self.assert_initialized();
        let owner = self.owner_of(OwnerOf {
            token_id: args.token_id,
        });
        if args.approved == owner {
            panic!("DRC721: approval to current owner");
        }
        if caller != owner
            && !self.is_approved_for_all(IsApprovedForAll {
                owner,
                operator: caller,
            })
        {
            panic!("{}", error::UNAUTHORIZED);
        }
        if args.approved.is_zero() {
            self.token_approvals.remove(&args.token_id);
        } else {
            self.token_approvals.insert(args.token_id, args.approved);
        }
        Approval {
            owner,
            approved: args.approved,
            token_id: args.token_id,
        }
    }

    /// Sets operator approval.
    pub fn set_approval_for_all(
        &mut self,
        caller: Principal,
        args: SetApprovalForAllCall,
    ) -> ApprovalForAll {
        self.assert_initialized();
        if args.operator.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if args.operator == caller {
            panic!("DRC721: approval to current owner");
        }
        self.operator_approvals
            .insert((caller, args.operator), args.approved);
        ApprovalForAll {
            owner: caller,
            operator: args.operator,
            approved: args.approved,
        }
    }

    /// Transfers a token.
    pub fn transfer_from(
        &mut self,
        caller: Principal,
        args: TransferFromCall,
    ) -> Transfer {
        self.assert_initialized();
        if args.to.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let owner = self.owner_of(OwnerOf {
            token_id: args.token_id,
        });
        if owner != args.from {
            panic!("DRC721: incorrect owner");
        }
        let approved = self.token_approvals.get(&args.token_id).copied();
        let operator = self.is_approved_for_all(IsApprovedForAll {
            owner,
            operator: caller,
        });
        if caller != owner && approved != Some(caller) && !operator {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.token_approvals.remove(&args.token_id);
        self.owners.insert(args.token_id, args.to);
        self.decrement_balance(owner);
        self.increment_balance(args.to);
        Transfer {
            from: owner,
            to: args.to,
            token_id: args.token_id,
        }
    }

    /// Mints a token. Access control belongs in the composing contract.
    pub fn mint(&mut self, to: Principal, token_id: u64) -> Transfer {
        self.assert_initialized();
        self.mint_internal(to, token_id);
        Transfer {
            from: ZERO_PRINCIPAL,
            to,
            token_id,
        }
    }

    /// Burns a token.
    pub fn burn(&mut self, caller: Principal, token_id: u64) -> Transfer {
        self.assert_initialized();
        let owner = self.owner_of(OwnerOf { token_id });
        let approved = self.token_approvals.get(&token_id).copied();
        if caller != owner && approved != Some(caller) {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.owners.remove(&token_id);
        self.token_approvals.remove(&token_id);
        self.decrement_balance(owner);
        self.supply = self.supply.checked_sub(1).expect(error::UNDERFLOW);
        Transfer {
            from: owner,
            to: ZERO_PRINCIPAL,
            token_id,
        }
    }

    fn assert_initialized(&self) {
        if !self.initialized {
            panic!("{}", error::NOT_INITIALIZED);
        }
    }

    fn mint_internal(&mut self, to: Principal, token_id: u64) {
        if to.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if self.owners.contains_key(&token_id) {
            panic!("DRC721: token already minted");
        }
        self.owners.insert(token_id, to);
        self.increment_balance(to);
        self.supply = self.supply.checked_add(1).expect(error::OVERFLOW);
    }

    fn require_exists(&self, token_id: u64) {
        if !self.owners.contains_key(&token_id) {
            panic!("DRC721: token does not exist");
        }
    }

    fn increment_balance(&mut self, owner: Principal) {
        let bal = self.balances.entry(owner).or_insert(0);
        *bal = bal.checked_add(1).expect(error::OVERFLOW);
    }

    fn decrement_balance(&mut self, owner: Principal) {
        let bal = self
            .balances
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("DRC721: incorrect owner"));
        *bal = bal.checked_sub(1).expect(error::UNDERFLOW);
        if *bal == 0 {
            self.balances.remove(&owner);
        }
    }
}

impl Default for Drc721 {
    fn default() -> Self {
        Self::new()
    }
}
