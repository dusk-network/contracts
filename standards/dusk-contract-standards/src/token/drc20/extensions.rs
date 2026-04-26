//! Optional DRC20 policy helpers.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::{error, Principal};

/// Supply cap policy.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SupplyCap {
    cap: u64,
}

impl SupplyCap {
    /// Creates a supply cap.
    pub const fn new(cap: u64) -> Self {
        Self { cap }
    }

    /// Returns the cap.
    pub const fn cap(&self) -> u64 {
        self.cap
    }

    /// Sets a new cap. The new cap must not be below current supply.
    pub fn set_cap(&mut self, current_supply: u64, cap: u64) {
        if cap < current_supply {
            panic!("DRC20: cap below current supply");
        }
        self.cap = cap;
    }

    /// Returns remaining mintable supply.
    pub const fn remaining(&self, current_supply: u64) -> u64 {
        self.cap.saturating_sub(current_supply)
    }

    /// Panics unless minting `amount` keeps supply within cap.
    pub fn assert_mint(&self, current_supply: u64, amount: u64) {
        let next = current_supply.checked_add(amount).expect(error::OVERFLOW);
        if next > self.cap {
            panic!("DRC20: cap exceeded");
        }
    }
}

/// Vote or accounting checkpoint.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Checkpoint {
    /// Block height, timestamp, epoch, or app-selected timepoint.
    pub key: u64,
    /// Value at that timepoint.
    pub value: u64,
}

/// Ordered checkpoint trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checkpoints {
    checkpoints: Vec<Checkpoint>,
}

impl Checkpoints {
    /// Creates an empty trace.
    pub const fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
        }
    }

    /// Returns all checkpoints.
    pub fn entries(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// Returns latest value or zero.
    pub fn latest(&self) -> u64 {
        self.checkpoints
            .last()
            .map(|checkpoint| checkpoint.value)
            .unwrap_or(0)
    }

    /// Writes a checkpoint.
    pub fn push(&mut self, key: u64, value: u64) {
        if let Some(last) = self.checkpoints.last_mut() {
            if key < last.key {
                panic!("Checkpoints: non-monotonic key");
            }
            if key == last.key {
                last.value = value;
                return;
            }
        }
        self.checkpoints.push(Checkpoint { key, value });
    }

    fn assert_can_push(&self, key: u64) {
        if let Some(last) = self.checkpoints.last() {
            if key < last.key {
                panic!("Checkpoints: non-monotonic key");
            }
        }
    }

    /// Returns value at or before `key`.
    pub fn get_at(&self, key: u64) -> u64 {
        let mut low = 0usize;
        let mut high = self.checkpoints.len();
        while low < high {
            let mid = (low + high) / 2;
            if self.checkpoints[mid].key <= key {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            0
        } else {
            self.checkpoints[low - 1].value
        }
    }
}

/// DRC20 voting-unit checkpoint store.
///
/// Composing contracts call `move_units` after mint, burn, and transfer hooks
/// when they want historical vote/accounting queries.
#[derive(Clone, Debug, Default)]
pub struct VotingUnits {
    accounts: BTreeMap<Principal, Checkpoints>,
    total_supply: Checkpoints,
}

impl VotingUnits {
    /// Creates empty voting-unit state.
    pub const fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
            total_supply: Checkpoints::new(),
        }
    }

    /// Returns latest account units.
    pub fn latest_votes(&self, account: Principal) -> u64 {
        self.accounts
            .get(&account)
            .map(Checkpoints::latest)
            .unwrap_or(0)
    }

    /// Returns historical account units.
    pub fn past_votes(&self, account: Principal, timepoint: u64) -> u64 {
        self.accounts
            .get(&account)
            .map(|trace| trace.get_at(timepoint))
            .unwrap_or(0)
    }

    /// Returns latest total units.
    pub fn latest_total_supply(&self) -> u64 {
        self.total_supply.latest()
    }

    /// Returns historical total units.
    pub fn past_total_supply(&self, timepoint: u64) -> u64 {
        self.total_supply.get_at(timepoint)
    }

    /// Writes an account checkpoint directly.
    pub fn write_votes(
        &mut self,
        account: Principal,
        timepoint: u64,
        value: u64,
    ) {
        self.accounts
            .entry(account)
            .or_default()
            .push(timepoint, value);
    }

    /// Moves units between accounts, minting from `None` or burning to `None`.
    pub fn move_units(
        &mut self,
        from: Option<Principal>,
        to: Option<Principal>,
        amount: u64,
        timepoint: u64,
    ) {
        if amount == 0 || from == to {
            return;
        }

        let from_next = if let Some(from) = from {
            let current = self.latest_votes(from);
            if current < amount {
                panic!("VotingUnits: insufficient units");
            }
            Some((from, current - amount))
        } else {
            None
        };

        let to_next = if let Some(to) = to {
            let current = self.latest_votes(to);
            let next = current.checked_add(amount).expect(error::OVERFLOW);
            Some((to, next))
        } else {
            None
        };

        let total_next = match (from, to) {
            (None, Some(_)) => Some(
                self.latest_total_supply()
                    .checked_add(amount)
                    .expect(error::OVERFLOW),
            ),
            (Some(_), None) => {
                let current = self.latest_total_supply();
                if current < amount {
                    panic!("VotingUnits: total supply underflow");
                }
                Some(current - amount)
            }
            _ => None,
        };

        if let Some((from, _)) = from_next {
            self.assert_can_write_votes(from, timepoint);
        }
        if let Some((to, _)) = to_next {
            self.assert_can_write_votes(to, timepoint);
        }
        if total_next.is_some() {
            self.total_supply.assert_can_push(timepoint);
        }

        if let Some((from, value)) = from_next {
            self.write_votes(from, timepoint, value);
        }
        if let Some((to, value)) = to_next {
            self.write_votes(to, timepoint, value);
        }
        if let Some(value) = total_next {
            self.total_supply.push(timepoint, value);
        }
    }

    fn assert_can_write_votes(&self, account: Principal, timepoint: u64) {
        if let Some(trace) = self.accounts.get(&account) {
            trace.assert_can_push(timepoint);
        }
    }
}
