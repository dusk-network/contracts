use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::core::Principal;
use dusk_contract_standards::token::drc20::{
    Allowance, ApproveCall, BalanceOf as BalanceOf20, DecreaseAllowanceCall,
    Drc20, IncreaseAllowanceCall, Init as Init20, InitBalance,
    TransferCall as Transfer20, TransferFromCall,
};
use dusk_contract_standards::token::drc721::{
    ApproveCall as Approve721, BalanceOf as BalanceOf721, Drc721, GetApproved,
    Init as Init721, InitToken, IsApprovedForAll, OwnerOf,
    SetApprovalForAllCall, TokensOf, TransferFromCall as Transfer721,
};
use dusk_core::abi::ContractId;
use proptest::prelude::*;

fn principal(index: u8) -> Principal {
    if index == 0 {
        Principal::Contract(ContractId::from_bytes([0u8; 32]))
    } else {
        Principal::Phoenix([index; 32])
    }
}

fn principal_strategy() -> BoxedStrategy<Principal> {
    (0u8..=5).prop_map(principal).boxed()
}

fn all_principals() -> Vec<Principal> {
    (0u8..=5).map(principal).collect()
}

#[derive(Clone, Debug)]
enum Drc20Op {
    Transfer {
        from: Principal,
        to: Principal,
        amount: u64,
    },
    Approve {
        owner: Principal,
        spender: Principal,
        amount: u64,
    },
    IncreaseAllowance {
        owner: Principal,
        spender: Principal,
        amount: u64,
    },
    DecreaseAllowance {
        owner: Principal,
        spender: Principal,
        amount: u64,
    },
    TransferFrom {
        spender: Principal,
        owner: Principal,
        to: Principal,
        amount: u64,
    },
    Mint {
        to: Principal,
        amount: u64,
    },
    Burn {
        from: Principal,
        amount: u64,
    },
}

fn drc20_op_strategy() -> impl Strategy<Value = Drc20Op> {
    let account = principal_strategy();
    let amount = 0u64..=150;
    prop_oneof![
        (account.clone(), account.clone(), amount.clone()).prop_map(
            |(from, to, amount)| Drc20Op::Transfer { from, to, amount },
        ),
        (account.clone(), account.clone(), amount.clone()).prop_map(
            |(owner, spender, amount)| Drc20Op::Approve {
                owner,
                spender,
                amount,
            },
        ),
        (account.clone(), account.clone(), amount.clone()).prop_map(
            |(owner, spender, amount)| Drc20Op::IncreaseAllowance {
                owner,
                spender,
                amount,
            },
        ),
        (account.clone(), account.clone(), amount.clone()).prop_map(
            |(owner, spender, amount)| Drc20Op::DecreaseAllowance {
                owner,
                spender,
                amount,
            },
        ),
        (
            account.clone(),
            account.clone(),
            account.clone(),
            amount.clone()
        )
            .prop_map(|(spender, owner, to, amount)| {
                Drc20Op::TransferFrom {
                    spender,
                    owner,
                    to,
                    amount,
                }
            }),
        (account.clone(), amount.clone())
            .prop_map(|(to, amount)| Drc20Op::Mint { to, amount }),
        (account, amount)
            .prop_map(|(from, amount)| Drc20Op::Burn { from, amount }),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Drc20Snapshot {
    total_supply: u64,
    balances: Vec<(Principal, u64)>,
    allowances: Vec<(Principal, Principal, u64)>,
}

#[derive(Clone, Debug)]
struct Drc20Model {
    balances: BTreeMap<Principal, u64>,
    allowances: BTreeMap<(Principal, Principal), u64>,
    total_supply: u64,
}

impl Drc20Model {
    fn initial() -> Self {
        let mut balances = BTreeMap::new();
        balances.insert(principal(1), 100);
        balances.insert(principal(2), 50);
        Self {
            balances,
            allowances: BTreeMap::new(),
            total_supply: 150,
        }
    }

    fn snapshot(&self, accounts: &[Principal]) -> Drc20Snapshot {
        let mut balances = Vec::new();
        let mut allowances = Vec::new();
        for &account in accounts {
            balances.push((account, self.balance(account)));
        }
        for &owner in accounts {
            for &spender in accounts {
                allowances.push((
                    owner,
                    spender,
                    self.allowance(owner, spender),
                ));
            }
        }
        Drc20Snapshot {
            total_supply: self.total_supply,
            balances,
            allowances,
        }
    }

    fn balance(&self, account: Principal) -> u64 {
        self.balances.get(&account).copied().unwrap_or(0)
    }

    fn allowance(&self, owner: Principal, spender: Principal) -> u64 {
        self.allowances.get(&(owner, spender)).copied().unwrap_or(0)
    }

    fn set_balance(&mut self, account: Principal, amount: u64) {
        if amount == 0 {
            self.balances.remove(&account);
        } else {
            self.balances.insert(account, amount);
        }
    }

    fn apply(&mut self, op: &Drc20Op) -> bool {
        match *op {
            Drc20Op::Transfer { from, to, amount } => {
                self.transfer(from, to, amount)
            }
            Drc20Op::Approve {
                owner,
                spender,
                amount,
            } => {
                if owner.is_zero() || spender.is_zero() {
                    return false;
                }
                self.allowances.insert((owner, spender), amount);
                true
            }
            Drc20Op::IncreaseAllowance {
                owner,
                spender,
                amount,
            } => {
                if owner.is_zero() || spender.is_zero() {
                    return false;
                }
                let Some(next) =
                    self.allowance(owner, spender).checked_add(amount)
                else {
                    return false;
                };
                self.allowances.insert((owner, spender), next);
                true
            }
            Drc20Op::DecreaseAllowance {
                owner,
                spender,
                amount,
            } => {
                if owner.is_zero() || spender.is_zero() {
                    return false;
                }
                let current = self.allowance(owner, spender);
                if current < amount {
                    return false;
                }
                self.allowances.insert((owner, spender), current - amount);
                true
            }
            Drc20Op::TransferFrom {
                spender,
                owner,
                to,
                amount,
            } => {
                if spender.is_zero() || self.allowance(owner, spender) < amount
                {
                    return false;
                }
                let before = self.clone();
                if !self.transfer(owner, to, amount) {
                    *self = before;
                    return false;
                }
                let current = self.allowance(owner, spender);
                self.allowances.insert((owner, spender), current - amount);
                true
            }
            Drc20Op::Mint { to, amount } => {
                if to.is_zero() {
                    return false;
                }
                let Some(next_balance) = self.balance(to).checked_add(amount)
                else {
                    return false;
                };
                let Some(next_supply) = self.total_supply.checked_add(amount)
                else {
                    return false;
                };
                self.set_balance(to, next_balance);
                self.total_supply = next_supply;
                true
            }
            Drc20Op::Burn { from, amount } => {
                if from.is_zero() || self.balance(from) < amount {
                    return false;
                }
                self.set_balance(from, self.balance(from) - amount);
                self.total_supply -= amount;
                true
            }
        }
    }

    fn transfer(
        &mut self,
        from: Principal,
        to: Principal,
        amount: u64,
    ) -> bool {
        if from.is_zero() || to.is_zero() || self.balance(from) < amount {
            return false;
        }
        if from != to && self.balance(to).checked_add(amount).is_none() {
            return false;
        }
        if amount != 0 {
            if from == to {
                return true;
            }
            self.set_balance(from, self.balance(from) - amount);
            self.set_balance(to, self.balance(to) + amount);
        }
        true
    }
}

fn drc20_snapshot(token: &Drc20, accounts: &[Principal]) -> Drc20Snapshot {
    let mut balances = Vec::new();
    let mut allowances = Vec::new();
    for &account in accounts {
        balances.push((account, token.balance_of(BalanceOf20 { account })));
    }
    for &owner in accounts {
        for &spender in accounts {
            allowances.push((
                owner,
                spender,
                token.allowance(Allowance { owner, spender }),
            ));
        }
    }
    Drc20Snapshot {
        total_supply: token.total_supply(),
        balances,
        allowances,
    }
}

fn apply_drc20_token(token: &mut Drc20, op: &Drc20Op) -> bool {
    catch_unwind(AssertUnwindSafe(|| match *op {
        Drc20Op::Transfer { from, to, amount } => {
            token.transfer(from, Transfer20 { to, amount });
        }
        Drc20Op::Approve {
            owner,
            spender,
            amount,
        } => {
            token.approve(owner, ApproveCall { spender, amount });
        }
        Drc20Op::IncreaseAllowance {
            owner,
            spender,
            amount,
        } => {
            token.increase_allowance(
                owner,
                IncreaseAllowanceCall {
                    spender,
                    added_amount: amount,
                },
            );
        }
        Drc20Op::DecreaseAllowance {
            owner,
            spender,
            amount,
        } => {
            token.decrease_allowance(
                owner,
                DecreaseAllowanceCall {
                    spender,
                    subtracted_amount: amount,
                },
            );
        }
        Drc20Op::TransferFrom {
            spender,
            owner,
            to,
            amount,
        } => {
            token
                .transfer_from(spender, TransferFromCall { owner, to, amount });
        }
        Drc20Op::Mint { to, amount } => {
            token.mint(to, amount);
        }
        Drc20Op::Burn { from, amount } => {
            token.burn(from, amount);
        }
    }))
    .is_ok()
}

#[derive(Clone, Debug)]
enum Drc721Op {
    Mint {
        to: Principal,
        token_id: u64,
    },
    Approve {
        caller: Principal,
        approved: Principal,
        token_id: u64,
    },
    SetApprovalForAll {
        owner: Principal,
        operator: Principal,
        approved: bool,
    },
    Transfer {
        caller: Principal,
        from: Principal,
        to: Principal,
        token_id: u64,
    },
    Burn {
        caller: Principal,
        token_id: u64,
    },
}

fn drc721_op_strategy() -> impl Strategy<Value = Drc721Op> {
    let account = principal_strategy();
    let token_id = 0u64..=8;
    prop_oneof![
        (account.clone(), token_id.clone())
            .prop_map(|(to, token_id)| Drc721Op::Mint { to, token_id }),
        (account.clone(), account.clone(), token_id.clone()).prop_map(
            |(caller, approved, token_id)| Drc721Op::Approve {
                caller,
                approved,
                token_id,
            },
        ),
        (account.clone(), account.clone(), any::<bool>()).prop_map(
            |(owner, operator, approved)| Drc721Op::SetApprovalForAll {
                owner,
                operator,
                approved,
            },
        ),
        (
            account.clone(),
            account.clone(),
            account.clone(),
            token_id.clone()
        )
            .prop_map(|(caller, from, to, token_id)| {
                Drc721Op::Transfer {
                    caller,
                    from,
                    to,
                    token_id,
                }
            }),
        (account, token_id)
            .prop_map(|(caller, token_id)| Drc721Op::Burn { caller, token_id }),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Drc721Snapshot {
    total_supply: u64,
    owners: Vec<(u64, Option<Principal>)>,
    balances: Vec<(Principal, u64)>,
    approvals: Vec<(u64, Option<Principal>)>,
    operators: Vec<(Principal, Principal, bool)>,
    tokens: Vec<(Principal, Vec<u64>)>,
}

#[derive(Clone, Debug)]
struct Drc721Model {
    owners: BTreeMap<u64, Principal>,
    approvals: BTreeMap<u64, Principal>,
    operators: BTreeMap<(Principal, Principal), bool>,
}

impl Drc721Model {
    fn initial() -> Self {
        let mut owners = BTreeMap::new();
        owners.insert(1, principal(1));
        owners.insert(2, principal(2));
        Self {
            owners,
            approvals: BTreeMap::new(),
            operators: BTreeMap::new(),
        }
    }

    fn snapshot(
        &self,
        accounts: &[Principal],
        token_ids: &[u64],
    ) -> Drc721Snapshot {
        let owners = token_ids
            .iter()
            .map(|&id| (id, self.owners.get(&id).copied()))
            .collect();
        let balances = accounts
            .iter()
            .copied()
            .filter(|account| !account.is_zero())
            .map(|account| (account, self.balance(account)))
            .collect();
        let approvals = token_ids
            .iter()
            .map(|&id| (id, self.approved(id)))
            .collect();
        let mut operators = Vec::new();
        for &owner in accounts {
            for &operator in accounts {
                operators.push((
                    owner,
                    operator,
                    self.is_operator(owner, operator),
                ));
            }
        }
        let tokens = accounts
            .iter()
            .copied()
            .map(|account| (account, self.tokens_of(account)))
            .collect();
        Drc721Snapshot {
            total_supply: self.owners.len() as u64,
            owners,
            balances,
            approvals,
            operators,
            tokens,
        }
    }

    fn balance(&self, account: Principal) -> u64 {
        self.owners
            .values()
            .filter(|&&owner| owner == account)
            .count() as u64
    }

    fn approved(&self, token_id: u64) -> Option<Principal> {
        if self.owners.contains_key(&token_id) {
            Some(
                self.approvals
                    .get(&token_id)
                    .copied()
                    .unwrap_or_else(|| principal(0)),
            )
        } else {
            None
        }
    }

    fn is_operator(&self, owner: Principal, operator: Principal) -> bool {
        self.operators
            .get(&(owner, operator))
            .copied()
            .unwrap_or(false)
    }

    fn tokens_of(&self, account: Principal) -> Vec<u64> {
        self.owners
            .iter()
            .filter_map(|(&token_id, &owner)| {
                if owner == account {
                    Some(token_id)
                } else {
                    None
                }
            })
            .collect()
    }

    fn apply(&mut self, op: &Drc721Op) -> bool {
        match *op {
            Drc721Op::Mint { to, token_id } => {
                if to.is_zero() || self.owners.contains_key(&token_id) {
                    return false;
                }
                self.owners.insert(token_id, to);
                true
            }
            Drc721Op::Approve {
                caller,
                approved,
                token_id,
            } => {
                let Some(&owner) = self.owners.get(&token_id) else {
                    return false;
                };
                if approved == owner {
                    return false;
                }
                if caller != owner && !self.is_operator(owner, caller) {
                    return false;
                }
                if approved.is_zero() {
                    self.approvals.remove(&token_id);
                } else {
                    self.approvals.insert(token_id, approved);
                }
                true
            }
            Drc721Op::SetApprovalForAll {
                owner,
                operator,
                approved,
            } => {
                if owner.is_zero() || operator.is_zero() || operator == owner {
                    return false;
                }
                self.operators.insert((owner, operator), approved);
                true
            }
            Drc721Op::Transfer {
                caller,
                from,
                to,
                token_id,
            } => {
                if to.is_zero() {
                    return false;
                }
                let Some(&owner) = self.owners.get(&token_id) else {
                    return false;
                };
                if owner != from {
                    return false;
                }
                let approved = self.approvals.get(&token_id).copied();
                if caller != owner
                    && approved != Some(caller)
                    && !self.is_operator(owner, caller)
                {
                    return false;
                }
                self.approvals.remove(&token_id);
                self.owners.insert(token_id, to);
                true
            }
            Drc721Op::Burn { caller, token_id } => {
                let Some(&owner) = self.owners.get(&token_id) else {
                    return false;
                };
                let approved = self.approvals.get(&token_id).copied();
                if caller != owner && approved != Some(caller) {
                    return false;
                }
                self.owners.remove(&token_id);
                self.approvals.remove(&token_id);
                true
            }
        }
    }
}

fn drc721_snapshot(
    token: &Drc721,
    accounts: &[Principal],
    token_ids: &[u64],
) -> Drc721Snapshot {
    let owners = token_ids
        .iter()
        .map(|&token_id| {
            let owner = catch_unwind(AssertUnwindSafe(|| {
                token.owner_of(OwnerOf { token_id })
            }))
            .ok();
            (token_id, owner)
        })
        .collect();
    let balances = accounts
        .iter()
        .copied()
        .filter(|account| !account.is_zero())
        .map(|account| (account, token.balance_of(BalanceOf721 { account })))
        .collect();
    let approvals = token_ids
        .iter()
        .map(|&token_id| {
            let approval = catch_unwind(AssertUnwindSafe(|| {
                token.get_approved(GetApproved { token_id })
            }))
            .ok();
            (token_id, approval)
        })
        .collect();
    let mut operators = Vec::new();
    for &owner in accounts {
        for &operator in accounts {
            operators.push((
                owner,
                operator,
                token.is_approved_for_all(IsApprovedForAll { owner, operator }),
            ));
        }
    }
    let tokens = accounts
        .iter()
        .copied()
        .map(|owner| (owner, token.tokens_of(TokensOf { owner })))
        .collect();
    Drc721Snapshot {
        total_supply: token.total_supply(),
        owners,
        balances,
        approvals,
        operators,
        tokens,
    }
}

fn apply_drc721_token(token: &mut Drc721, op: &Drc721Op) -> bool {
    catch_unwind(AssertUnwindSafe(|| match *op {
        Drc721Op::Mint { to, token_id } => {
            token.mint(to, token_id);
        }
        Drc721Op::Approve {
            caller,
            approved,
            token_id,
        } => {
            token.approve(caller, Approve721 { approved, token_id });
        }
        Drc721Op::SetApprovalForAll {
            owner,
            operator,
            approved,
        } => {
            token.set_approval_for_all(
                owner,
                SetApprovalForAllCall { operator, approved },
            );
        }
        Drc721Op::Transfer {
            caller,
            from,
            to,
            token_id,
        } => {
            token.transfer_from(caller, Transfer721 { from, to, token_id });
        }
        Drc721Op::Burn { caller, token_id } => {
            token.burn(caller, token_id);
        }
    }))
    .is_ok()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    #[test]
    fn drc20_state_matches_model_and_failed_calls_are_atomic(
        ops in prop::collection::vec(drc20_op_strategy(), 0..160),
    ) {
        let accounts = all_principals();
        let mut token = Drc20::new();
        token.init(Init20 {
            name: "Property Token".into(),
            symbol: "PROP".into(),
            decimals: 9,
            initial_balances: vec![
                InitBalance { account: principal(1), amount: 100 },
                InitBalance { account: principal(2), amount: 50 },
            ],
        });
        let mut model = Drc20Model::initial();
        prop_assert_eq!(drc20_snapshot(&token, &accounts), model.snapshot(&accounts));

        for op in ops {
            let before = drc20_snapshot(&token, &accounts);
            let expected = model.apply(&op);
            let actual = apply_drc20_token(&mut token, &op);
            prop_assert_eq!(actual, expected, "operation diverged: {:?}", op);
            if expected {
                prop_assert_eq!(
                    drc20_snapshot(&token, &accounts),
                    model.snapshot(&accounts),
                    "successful operation left an unexpected state: {:?}",
                    op,
                );
            } else {
                prop_assert_eq!(
                    drc20_snapshot(&token, &accounts),
                    before,
                    "failed operation mutated state: {:?}",
                    op,
                );
            }
        }
    }

    #[test]
    fn drc721_state_matches_model_and_failed_calls_are_atomic(
        ops in prop::collection::vec(drc721_op_strategy(), 0..140),
    ) {
        let accounts = all_principals();
        let token_ids: Vec<u64> = (0..=8).collect();
        let mut token = Drc721::new();
        token.init(Init721 {
            name: "Property NFT".into(),
            symbol: "PNFT".into(),
            base_uri: "ipfs://property/".into(),
            initial_tokens: vec![
                InitToken { account: principal(1), token_id: 1 },
                InitToken { account: principal(2), token_id: 2 },
            ],
        });
        let mut model = Drc721Model::initial();
        prop_assert_eq!(
            drc721_snapshot(&token, &accounts, &token_ids),
            model.snapshot(&accounts, &token_ids),
        );

        for op in ops {
            let before = drc721_snapshot(&token, &accounts, &token_ids);
            let expected = model.apply(&op);
            let actual = apply_drc721_token(&mut token, &op);
            prop_assert_eq!(actual, expected, "operation diverged: {:?}", op);
            if expected {
                prop_assert_eq!(
                    drc721_snapshot(&token, &accounts, &token_ids),
                    model.snapshot(&accounts, &token_ids),
                    "successful operation left an unexpected state: {:?}",
                    op,
                );
            } else {
                prop_assert_eq!(
                    drc721_snapshot(&token, &accounts, &token_ids),
                    before,
                    "failed operation mutated state: {:?}",
                    op,
                );
            }
        }
    }
}
