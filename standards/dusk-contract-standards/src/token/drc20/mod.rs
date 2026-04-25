//! DRC20 fungible token primitive.

pub mod events;
pub mod extensions;
pub mod types;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::core::{error, Principal};
use events::{Approval, Transfer};
pub use extensions::{Checkpoint, Checkpoints, SupplyCap, VotingUnits};
pub use types::{
    Allowance, ApproveCall, BalanceOf, DecreaseAllowanceCall,
    IncreaseAllowanceCall, Init, InitBalance, SignedApproveCall, TransferCall,
    TransferFromCall,
};

/// Reserved zero principal.
pub const ZERO_PRINCIPAL: Principal =
    Principal::Contract(dusk_core::abi::ContractId::from_bytes([0u8; 32]));

/// DRC20 token state and logic.
#[derive(Clone, Debug)]
pub struct Drc20 {
    initialized: bool,
    name: String,
    symbol: String,
    decimals: u8,
    balances: BTreeMap<Principal, u64>,
    allowances: BTreeMap<(Principal, Principal), u64>,
    supply: u64,
}

impl Drc20 {
    /// Creates empty token state.
    pub const fn new() -> Self {
        Self {
            initialized: false,
            name: String::new(),
            symbol: String::new(),
            decimals: 0,
            balances: BTreeMap::new(),
            allowances: BTreeMap::new(),
            supply: 0,
        }
    }

    /// Initializes token metadata and initial supply.
    pub fn init(&mut self, args: Init) -> Vec<Transfer> {
        if self.initialized {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        let mut initial_supply = 0u64;
        for entry in &args.initial_balances {
            if entry.account.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            initial_supply = initial_supply
                .checked_add(entry.amount)
                .expect(error::OVERFLOW);
        }

        self.initialized = true;
        self.name = args.name;
        self.symbol = args.symbol;
        self.decimals = args.decimals;

        let mut events = Vec::new();
        for entry in args.initial_balances {
            if entry.amount == 0 {
                continue;
            }
            self.mint_internal(entry.account, entry.amount);
            events.push(Transfer {
                from: ZERO_PRINCIPAL,
                to: entry.account,
                amount: entry.amount,
            });
        }
        events
    }

    /// Token name.
    pub fn name(&self) -> String {
        self.assert_initialized();
        self.name.clone()
    }

    /// Token symbol.
    pub fn symbol(&self) -> String {
        self.assert_initialized();
        self.symbol.clone()
    }

    /// Token decimals.
    pub fn decimals(&self) -> u8 {
        self.assert_initialized();
        self.decimals
    }

    /// Total supply.
    pub fn total_supply(&self) -> u64 {
        self.assert_initialized();
        self.supply
    }

    /// Balance of `account`.
    pub fn balance_of(&self, args: BalanceOf) -> u64 {
        self.assert_initialized();
        self.balances.get(&args.account).copied().unwrap_or(0)
    }

    /// Allowance from owner to spender.
    pub fn allowance(&self, args: Allowance) -> u64 {
        self.assert_initialized();
        self.allowances
            .get(&(args.owner, args.spender))
            .copied()
            .unwrap_or(0)
    }

    /// Transfers from caller to recipient.
    pub fn transfer(
        &mut self,
        caller: Principal,
        args: TransferCall,
    ) -> Transfer {
        self.assert_initialized();
        self.transfer_internal(caller, args.to, args.amount)
    }

    /// Approves spender.
    pub fn approve(
        &mut self,
        caller: Principal,
        args: ApproveCall,
    ) -> Approval {
        self.approve_for(caller, args)
    }

    /// Approves spender for an explicitly authorized owner.
    pub fn approve_for(
        &mut self,
        owner: Principal,
        args: ApproveCall,
    ) -> Approval {
        self.assert_initialized();
        if args.spender.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.allowances.insert((owner, args.spender), args.amount);
        Approval {
            owner,
            spender: args.spender,
            amount: args.amount,
        }
    }

    /// Increases spender allowance.
    pub fn increase_allowance(
        &mut self,
        caller: Principal,
        args: IncreaseAllowanceCall,
    ) -> Approval {
        self.assert_initialized();
        if args.spender.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let current = self.allowance(Allowance {
            owner: caller,
            spender: args.spender,
        });
        let amount = current
            .checked_add(args.added_amount)
            .expect(error::OVERFLOW);
        self.allowances.insert((caller, args.spender), amount);
        Approval {
            owner: caller,
            spender: args.spender,
            amount,
        }
    }

    /// Decreases spender allowance.
    pub fn decrease_allowance(
        &mut self,
        caller: Principal,
        args: DecreaseAllowanceCall,
    ) -> Approval {
        self.assert_initialized();
        let current = self.allowance(Allowance {
            owner: caller,
            spender: args.spender,
        });
        if current < args.subtracted_amount {
            panic!("DRC20: allowance below zero");
        }
        let amount = current - args.subtracted_amount;
        self.allowances.insert((caller, args.spender), amount);
        Approval {
            owner: caller,
            spender: args.spender,
            amount,
        }
    }

    /// Transfers using allowance.
    pub fn transfer_from(
        &mut self,
        caller: Principal,
        args: TransferFromCall,
    ) -> Transfer {
        self.assert_initialized();
        let current = self.allowance(Allowance {
            owner: args.owner,
            spender: caller,
        });
        if current < args.amount {
            panic!("DRC20: allowance too low");
        }
        self.allowances
            .insert((args.owner, caller), current - args.amount);
        self.transfer_internal(args.owner, args.to, args.amount)
    }

    /// Mints tokens. Access control belongs in the composing contract.
    pub fn mint(&mut self, to: Principal, amount: u64) -> Transfer {
        self.assert_initialized();
        self.mint_internal(to, amount);
        Transfer {
            from: ZERO_PRINCIPAL,
            to,
            amount,
        }
    }

    /// Burns caller tokens.
    pub fn burn(&mut self, from: Principal, amount: u64) -> Transfer {
        self.assert_initialized();
        self.burn_internal(from, amount);
        Transfer {
            from,
            to: ZERO_PRINCIPAL,
            amount,
        }
    }

    fn assert_initialized(&self) {
        if !self.initialized {
            panic!("{}", error::NOT_INITIALIZED);
        }
    }

    fn mint_internal(&mut self, to: Principal, amount: u64) {
        if to.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let bal = self.balances.entry(to).or_insert(0);
        *bal = bal.checked_add(amount).expect(error::OVERFLOW);
        self.supply = self.supply.checked_add(amount).expect(error::OVERFLOW);
    }

    fn burn_internal(&mut self, from: Principal, amount: u64) {
        let current = self.balances.get(&from).copied().unwrap_or(0);
        if current < amount {
            panic!("DRC20: balance too low");
        }
        if amount != 0 {
            let next = current - amount;
            if next == 0 {
                self.balances.remove(&from);
            } else {
                self.balances.insert(from, next);
            }
            self.supply =
                self.supply.checked_sub(amount).expect(error::UNDERFLOW);
        }
    }

    fn transfer_internal(
        &mut self,
        from: Principal,
        to: Principal,
        amount: u64,
    ) -> Transfer {
        if to.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let current = self.balances.get(&from).copied().unwrap_or(0);
        if current < amount {
            panic!("DRC20: balance too low");
        }
        if amount != 0 {
            let next = current - amount;
            if next == 0 {
                self.balances.remove(&from);
            } else {
                self.balances.insert(from, next);
            }
            let to_balance = self.balances.entry(to).or_insert(0);
            *to_balance =
                to_balance.checked_add(amount).expect(error::OVERFLOW);
        }
        Transfer { from, to, amount }
    }
}

impl Default for Drc20 {
    fn default() -> Self {
        Self::new()
    }
}
