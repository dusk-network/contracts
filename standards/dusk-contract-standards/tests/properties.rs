use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::access::{
    AccessControl, OwnerSet, DEFAULT_ADMIN_ROLE,
};
use dusk_contract_standards::auth::{
    ActionEnvelope, AuthorizationManager, AuthorizedAction,
    MoonlightAuthorization, SignedAuthorization,
};
use dusk_contract_standards::core::{CallContext, Principal};
use dusk_contract_standards::governance::Timelock;
use dusk_contract_standards::proxy::UpgradeAdmin;
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
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

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

fn contract_id(index: u8) -> ContractId {
    ContractId::from_bytes([index; 32])
}

fn role(index: u8) -> [u8; 32] {
    let mut role = [0u8; 32];
    role[0] = index;
    role
}

fn amount_strategy() -> BoxedStrategy<u64> {
    prop_oneof![
        12 => 0u64..=150,
        2 => (0u64..=16).prop_map(|delta| u64::MAX - delta),
        1 => Just(u64::MAX),
    ]
    .boxed()
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
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
    let amount = amount_strategy();
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

#[derive(Clone, Copy, Debug)]
enum AuthCase {
    Good,
    WrongContract,
    WrongDomain,
    WrongAction,
    WrongPayload,
    Expired,
    FutureNonce,
    BadPrincipal,
    BadSignature,
    WrongExpected,
    OwnerSetNonOwner,
    RoleNonMember,
    AdminMismatch,
}

fn auth_case_strategy() -> impl Strategy<Value = AuthCase> {
    prop_oneof![
        Just(AuthCase::Good),
        Just(AuthCase::WrongContract),
        Just(AuthCase::WrongDomain),
        Just(AuthCase::WrongAction),
        Just(AuthCase::WrongPayload),
        Just(AuthCase::Expired),
        Just(AuthCase::FutureNonce),
        Just(AuthCase::BadPrincipal),
        Just(AuthCase::BadSignature),
        Just(AuthCase::WrongExpected),
        Just(AuthCase::OwnerSetNonOwner),
        Just(AuthCase::RoleNonMember),
        Just(AuthCase::AdminMismatch),
    ]
}

fn signed_action(
    secret: &BlsSecretKey,
    public: BlsPublicKey,
    action: AuthorizedAction,
) -> SignedAuthorization {
    SignedAuthorization::Moonlight(MoonlightAuthorization {
        action,
        public_key: public,
        signature: secret.sign(&action.message_bytes()),
    })
}

fn authorization_probe(case: AuthCase) -> (bool, u64) {
    let secret = moonlight_secret(31);
    let public = BlsPublicKey::from(&secret);
    let signer = Principal::moonlight(&public);
    let contract = contract_id(32);
    let domain = [33u8; 32];
    let action_id = [34u8; 32];
    let payload_hash = [35u8; 32];
    let envelope =
        ActionEnvelope::new(contract, domain, action_id, payload_hash);
    let mut action = AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce: 0,
        expires_at: 100,
        principal: signer,
        payload_hash,
    };
    let mut now = 100;
    let expected = match case {
        AuthCase::Good => signer,
        AuthCase::WrongExpected => principal(1),
        AuthCase::WrongContract => {
            action.contract = contract_id(36);
            signer
        }
        AuthCase::WrongDomain => {
            action.domain = [37u8; 32];
            signer
        }
        AuthCase::WrongAction => {
            action.action_id = [38u8; 32];
            signer
        }
        AuthCase::WrongPayload => {
            action.payload_hash = [39u8; 32];
            signer
        }
        AuthCase::Expired => {
            now = 101;
            signer
        }
        AuthCase::FutureNonce => {
            action.nonce = 1;
            signer
        }
        AuthCase::BadPrincipal => {
            action.principal = principal(2);
            signer
        }
        AuthCase::BadSignature
        | AuthCase::OwnerSetNonOwner
        | AuthCase::RoleNonMember
        | AuthCase::AdminMismatch => signer,
    };

    let signed = if matches!(case, AuthCase::BadSignature) {
        let original = action;
        action.payload_hash = [42u8; 32];
        SignedAuthorization::Moonlight(MoonlightAuthorization {
            action,
            public_key: public,
            signature: secret.sign(&original.message_bytes()),
        })
    } else {
        signed_action(&secret, public, action)
    };

    let mut authorizations = AuthorizationManager::new();
    let result = catch_unwind(AssertUnwindSafe(|| match case {
        AuthCase::OwnerSetNonOwner => {
            let mut owners = OwnerSet::new();
            owners.init([principal(1)]);
            owners.authorize_owner_action(
                &mut authorizations,
                CallContext::none(),
                Some(&signed),
                envelope,
                now,
            );
        }
        AuthCase::RoleNonMember => {
            let checked_role = role(40);
            let mut access = AccessControl::new();
            access.init_admin(principal(1));
            access.grant_role(principal(1), checked_role, principal(2));
            access.authorize_role_action(
                checked_role,
                &mut authorizations,
                CallContext::none(),
                Some(&signed),
                envelope,
                now,
            );
        }
        AuthCase::AdminMismatch => {
            let upgrade =
                UpgradeAdmin::new(principal(1), contract_id(41), 0, 0);
            upgrade.authorize_admin_action(
                &mut authorizations,
                CallContext::none(),
                Some(&signed),
                envelope,
                now,
            );
        }
        _ => {
            authorizations.authorize_principal_action(
                expected,
                CallContext::none(),
                Some(&signed),
                envelope,
                now,
            );
        }
    }))
    .is_ok();
    (result, authorizations.nonce(signer, domain))
}

#[derive(Clone, Debug)]
enum OwnerSetOp {
    Add {
        caller: Principal,
        owner: Principal,
    },
    Remove {
        caller: Principal,
        owner: Principal,
    },
    Replace {
        caller: Principal,
        old_owner: Principal,
        new_owner: Principal,
    },
}

fn owner_set_op_strategy() -> impl Strategy<Value = OwnerSetOp> {
    let account = principal_strategy();
    prop_oneof![
        (account.clone(), account.clone())
            .prop_map(|(caller, owner)| { OwnerSetOp::Add { caller, owner } }),
        (account.clone(), account.clone()).prop_map(|(caller, owner)| {
            OwnerSetOp::Remove { caller, owner }
        }),
        (account.clone(), account.clone(), account).prop_map(
            |(caller, old_owner, new_owner)| OwnerSetOp::Replace {
                caller,
                old_owner,
                new_owner,
            },
        ),
    ]
}

fn apply_owner_set_model(
    owners: &mut BTreeSet<Principal>,
    op: &OwnerSetOp,
) -> bool {
    match *op {
        OwnerSetOp::Add { caller, owner } => {
            if !owners.contains(&caller) || owner.is_zero() {
                return false;
            }
            owners.insert(owner);
            true
        }
        OwnerSetOp::Remove { caller, owner } => {
            if !owners.contains(&caller)
                || !owners.contains(&owner)
                || owners.len() == 1
            {
                return false;
            }
            owners.remove(&owner);
            true
        }
        OwnerSetOp::Replace {
            caller,
            old_owner,
            new_owner,
        } => {
            if !owners.contains(&caller)
                || new_owner.is_zero()
                || !owners.contains(&old_owner)
                || (old_owner != new_owner && owners.contains(&new_owner))
            {
                return false;
            }
            owners.remove(&old_owner);
            owners.insert(new_owner);
            true
        }
    }
}

fn apply_owner_set(owners: &mut OwnerSet, op: &OwnerSetOp) -> bool {
    catch_unwind(AssertUnwindSafe(|| match *op {
        OwnerSetOp::Add { caller, owner } => owners.add_owner(caller, owner),
        OwnerSetOp::Remove { caller, owner } => {
            owners.remove_owner(caller, owner)
        }
        OwnerSetOp::Replace {
            caller,
            old_owner,
            new_owner,
        } => owners.replace_owner(caller, old_owner, new_owner),
    }))
    .is_ok()
}

#[derive(Clone, Debug)]
enum AccessOp {
    Grant {
        caller: Principal,
        role: [u8; 32],
        account: Principal,
    },
    Revoke {
        caller: Principal,
        role: [u8; 32],
        account: Principal,
    },
    Renounce {
        role: [u8; 32],
        caller: Principal,
    },
    SetRoleAdmin {
        caller: Principal,
        role: [u8; 32],
        admin_role: [u8; 32],
    },
}

#[derive(Clone, Debug)]
struct RoleModel {
    members: BTreeSet<Principal>,
    admin_role: [u8; 32],
}

#[derive(Clone, Debug)]
struct AccessModel {
    roles: BTreeMap<[u8; 32], RoleModel>,
}

impl AccessModel {
    fn new(admin: Principal) -> Self {
        let mut members = BTreeSet::new();
        members.insert(admin);
        let mut roles = BTreeMap::new();
        roles.insert(
            DEFAULT_ADMIN_ROLE,
            RoleModel {
                members,
                admin_role: DEFAULT_ADMIN_ROLE,
            },
        );
        Self { roles }
    }

    fn has_role(&self, role: [u8; 32], account: Principal) -> bool {
        self.roles
            .get(&role)
            .map(|role| role.members.contains(&account))
            .unwrap_or(false)
    }

    fn role_admin(&self, role: [u8; 32]) -> [u8; 32] {
        self.roles
            .get(&role)
            .map(|role| role.admin_role)
            .unwrap_or(DEFAULT_ADMIN_ROLE)
    }

    fn apply(&mut self, op: &AccessOp) -> bool {
        match *op {
            AccessOp::Grant {
                caller,
                role,
                account,
            } => {
                if account.is_zero()
                    || !self.has_role(self.role_admin(role), caller)
                {
                    return false;
                }
                self.roles
                    .entry(role)
                    .or_insert_with(|| RoleModel {
                        members: BTreeSet::new(),
                        admin_role: DEFAULT_ADMIN_ROLE,
                    })
                    .members
                    .insert(account);
                true
            }
            AccessOp::Revoke {
                caller,
                role,
                account,
            } => {
                if !self.has_role(self.role_admin(role), caller) {
                    return false;
                }
                if let Some(role) = self.roles.get_mut(&role) {
                    role.members.remove(&account);
                }
                true
            }
            AccessOp::Renounce { role, caller } => {
                if let Some(role) = self.roles.get_mut(&role) {
                    role.members.remove(&caller);
                }
                true
            }
            AccessOp::SetRoleAdmin {
                caller,
                role,
                admin_role,
            } => {
                if !self.has_role(self.role_admin(role), caller) {
                    return false;
                }
                self.roles
                    .entry(role)
                    .or_insert_with(|| RoleModel {
                        members: BTreeSet::new(),
                        admin_role: DEFAULT_ADMIN_ROLE,
                    })
                    .admin_role = admin_role;
                true
            }
        }
    }

    fn snapshot(
        &self,
        roles: &[[u8; 32]],
        accounts: &[Principal],
    ) -> AccessSnapshot {
        AccessSnapshot {
            admins: roles
                .iter()
                .copied()
                .map(|role| (role, self.role_admin(role)))
                .collect(),
            memberships: roles
                .iter()
                .copied()
                .flat_map(|role| {
                    accounts.iter().copied().map(move |account| {
                        (role, account, self.has_role(role, account))
                    })
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccessSnapshot {
    admins: Vec<([u8; 32], [u8; 32])>,
    memberships: Vec<([u8; 32], Principal, bool)>,
}

fn access_op_strategy() -> impl Strategy<Value = AccessOp> {
    let account = principal_strategy();
    let role_strategy =
        (0u8..=3).prop_map(
            |i| {
                if i == 0 {
                    DEFAULT_ADMIN_ROLE
                } else {
                    role(i)
                }
            },
        );
    prop_oneof![
        (account.clone(), role_strategy.clone(), account.clone()).prop_map(
            |(caller, role, account)| AccessOp::Grant {
                caller,
                role,
                account,
            },
        ),
        (account.clone(), role_strategy.clone(), account.clone()).prop_map(
            |(caller, role, account)| AccessOp::Revoke {
                caller,
                role,
                account,
            },
        ),
        (role_strategy.clone(), account.clone())
            .prop_map(|(role, caller)| AccessOp::Renounce { role, caller },),
        (account, role_strategy.clone(), role_strategy).prop_map(
            |(caller, role, admin_role)| AccessOp::SetRoleAdmin {
                caller,
                role,
                admin_role,
            },
        ),
    ]
}

fn access_snapshot(
    access: &AccessControl,
    roles: &[[u8; 32]],
    accounts: &[Principal],
) -> AccessSnapshot {
    AccessSnapshot {
        admins: roles
            .iter()
            .copied()
            .map(|role| (role, access.get_role_admin(role)))
            .collect(),
        memberships: roles
            .iter()
            .copied()
            .flat_map(|role| {
                accounts.iter().copied().map(move |account| {
                    (role, account, access.has_role(role, account))
                })
            })
            .collect(),
    }
}

fn apply_access(access: &mut AccessControl, op: &AccessOp) -> bool {
    catch_unwind(AssertUnwindSafe(|| match *op {
        AccessOp::Grant {
            caller,
            role,
            account,
        } => access.grant_role(caller, role, account),
        AccessOp::Revoke {
            caller,
            role,
            account,
        } => access.revoke_role(caller, role, account),
        AccessOp::Renounce { role, caller } => {
            access.renounce_role(role, caller)
        }
        AccessOp::SetRoleAdmin {
            caller,
            role,
            admin_role,
        } => access.set_role_admin(caller, role, admin_role),
    }))
    .is_ok()
}

#[derive(Clone, Debug)]
enum TimelockOp {
    SetDelay {
        delay: u64,
    },
    Schedule {
        id: [u8; 32],
        now: u64,
        payload: Vec<u8>,
    },
    Cancel {
        id: [u8; 32],
    },
    Execute {
        id: [u8; 32],
        now: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TimelockSnapshot {
    min_delay: u64,
    operations: Vec<TimelockOperationSnapshot>,
}

type TimelockOperationSnapshot = ([u8; 32], Option<(u64, bool, Vec<u8>)>);

#[derive(Clone, Debug)]
struct TimelockModel {
    min_delay: u64,
    operations: BTreeMap<[u8; 32], (u64, bool, Vec<u8>)>,
}

impl TimelockModel {
    fn new(min_delay: u64) -> Self {
        Self {
            min_delay,
            operations: BTreeMap::new(),
        }
    }

    fn apply(&mut self, op: &TimelockOp) -> bool {
        match op {
            TimelockOp::SetDelay { delay } => {
                self.min_delay = *delay;
                true
            }
            TimelockOp::Schedule { id, now, payload } => {
                if self.operations.contains_key(id) {
                    return false;
                }
                let Some(ready_at) = now.checked_add(self.min_delay) else {
                    return false;
                };
                self.operations
                    .insert(*id, (ready_at, false, payload.clone()));
                true
            }
            TimelockOp::Cancel { id } => {
                let Some((_, done, _)) = self.operations.get(id) else {
                    return false;
                };
                if *done {
                    return false;
                }
                self.operations.remove(id);
                true
            }
            TimelockOp::Execute { id, now } => {
                let Some((ready_at, done, _)) = self.operations.get_mut(id)
                else {
                    return false;
                };
                if *done || *now < *ready_at {
                    return false;
                }
                *done = true;
                true
            }
        }
    }

    fn snapshot(&self, ids: &[[u8; 32]]) -> TimelockSnapshot {
        TimelockSnapshot {
            min_delay: self.min_delay,
            operations: ids
                .iter()
                .copied()
                .map(|id| (id, self.operations.get(&id).cloned()))
                .collect(),
        }
    }
}

fn timelock_op_strategy() -> impl Strategy<Value = TimelockOp> {
    let id = (0u8..=5).prop_map(|i| [i; 32]);
    let now = prop_oneof![0u64..=64, (0u64..=8).prop_map(|d| u64::MAX - d)];
    let payload = prop::collection::vec(0u8..=5, 0..4);
    prop_oneof![
        (0u64..=16).prop_map(|delay| TimelockOp::SetDelay { delay }),
        (id.clone(), now.clone(), payload).prop_map(|(id, now, payload)| {
            TimelockOp::Schedule { id, now, payload }
        },),
        id.clone().prop_map(|id| TimelockOp::Cancel { id }),
        (id, now).prop_map(|(id, now)| TimelockOp::Execute { id, now }),
    ]
}

fn timelock_snapshot(
    timelock: &Timelock,
    ids: &[[u8; 32]],
) -> TimelockSnapshot {
    TimelockSnapshot {
        min_delay: timelock.min_delay(),
        operations: ids
            .iter()
            .copied()
            .map(|id| {
                (
                    id,
                    timelock
                        .get(id)
                        .map(|op| (op.ready_at, op.done, op.payload.clone())),
                )
            })
            .collect(),
    }
}

fn apply_timelock(timelock: &mut Timelock, op: &TimelockOp) -> bool {
    catch_unwind(AssertUnwindSafe(|| match op {
        TimelockOp::SetDelay { delay } => timelock.set_min_delay(*delay),
        TimelockOp::Schedule { id, now, payload } => {
            timelock.schedule(*id, *now, payload.clone());
        }
        TimelockOp::Cancel { id } => timelock.cancel(*id),
        TimelockOp::Execute { id, now } => {
            timelock.execute(*id, *now);
        }
    }))
    .is_ok()
}

#[derive(Clone, Debug)]
enum UpgradeOp {
    Prepare {
        caller: Principal,
        implementation: ContractId,
        now: u64,
        payload: Vec<u8>,
    },
    Activate {
        caller: Principal,
        now: u64,
    },
    Cancel {
        caller: Principal,
    },
    Rollback {
        caller: Principal,
        now: u64,
    },
    Finalize {
        caller: Principal,
        now: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpgradeSnapshot {
    implementation: ContractId,
    pending: Option<(ContractId, u64, Vec<u8>)>,
    rollback_deadline: u64,
}

#[derive(Clone, Debug)]
struct UpgradeModel {
    admin: Principal,
    implementation: ContractId,
    previous: Option<ContractId>,
    pending: Option<(ContractId, u64, Vec<u8>)>,
    delay: u64,
    rollback_window: u64,
    rollback_deadline: u64,
}

impl UpgradeModel {
    fn new(admin: Principal, implementation: ContractId) -> Self {
        Self {
            admin,
            implementation,
            previous: None,
            pending: None,
            delay: 5,
            rollback_window: 10,
            rollback_deadline: 0,
        }
    }

    fn apply(&mut self, op: &UpgradeOp) -> bool {
        match op {
            UpgradeOp::Prepare {
                caller,
                implementation,
                now,
                payload,
            } => {
                if *caller != self.admin || is_zero_contract_id(*implementation)
                {
                    return false;
                }
                let Some(eta) = now.checked_add(self.delay) else {
                    return false;
                };
                self.pending = Some((*implementation, eta, payload.clone()));
                true
            }
            UpgradeOp::Activate { caller, now } => {
                if *caller != self.admin {
                    return false;
                }
                let Some((implementation, eta, _)) = self.pending.clone()
                else {
                    return false;
                };
                if *now < eta {
                    return false;
                }
                let Some(deadline) = now.checked_add(self.rollback_window)
                else {
                    return false;
                };
                self.previous = Some(self.implementation);
                self.implementation = implementation;
                self.pending = None;
                self.rollback_deadline = deadline;
                true
            }
            UpgradeOp::Cancel { caller } => {
                if *caller != self.admin || self.pending.is_none() {
                    return false;
                }
                self.pending = None;
                true
            }
            UpgradeOp::Rollback { caller, now } => {
                if *caller != self.admin
                    || self.rollback_deadline == 0
                    || *now > self.rollback_deadline
                {
                    return false;
                }
                let Some(previous) = self.previous.take() else {
                    return false;
                };
                self.implementation = previous;
                self.pending = None;
                self.rollback_deadline = 0;
                true
            }
            UpgradeOp::Finalize { caller, now } => {
                if *caller != self.admin
                    || (self.rollback_deadline != 0
                        && *now < self.rollback_deadline)
                {
                    return false;
                }
                self.previous = None;
                self.rollback_deadline = 0;
                true
            }
        }
    }

    fn snapshot(&self) -> UpgradeSnapshot {
        UpgradeSnapshot {
            implementation: self.implementation,
            pending: self.pending.clone(),
            rollback_deadline: self.rollback_deadline,
        }
    }
}

fn upgrade_op_strategy() -> impl Strategy<Value = UpgradeOp> {
    let account = principal_strategy();
    let implementation = (0u8..=5).prop_map(contract_id);
    let now = prop_oneof![0u64..=32, (0u64..=12).prop_map(|d| u64::MAX - d)];
    let payload = prop::collection::vec(0u8..=9, 0..4);
    prop_oneof![
        (account.clone(), implementation, now.clone(), payload).prop_map(
            |(caller, implementation, now, payload)| {
                UpgradeOp::Prepare {
                    caller,
                    implementation,
                    now,
                    payload,
                }
            }
        ),
        (account.clone(), now.clone())
            .prop_map(|(caller, now)| { UpgradeOp::Activate { caller, now } }),
        account
            .clone()
            .prop_map(|caller| UpgradeOp::Cancel { caller }),
        (account.clone(), now.clone())
            .prop_map(|(caller, now)| { UpgradeOp::Rollback { caller, now } }),
        (account, now)
            .prop_map(|(caller, now)| UpgradeOp::Finalize { caller, now }),
    ]
}

fn upgrade_snapshot(upgrade: &UpgradeAdmin) -> UpgradeSnapshot {
    UpgradeSnapshot {
        implementation: upgrade.implementation(),
        pending: upgrade.pending().map(|pending| {
            (
                pending.implementation,
                pending.eta,
                pending.migrate_data.clone(),
            )
        }),
        rollback_deadline: upgrade.rollback_deadline(),
    }
}

fn apply_upgrade(upgrade: &mut UpgradeAdmin, op: &UpgradeOp) -> bool {
    catch_unwind(AssertUnwindSafe(|| match op {
        UpgradeOp::Prepare {
            caller,
            implementation,
            now,
            payload,
        } => {
            upgrade.prepare(*caller, *implementation, *now, payload.clone());
        }
        UpgradeOp::Activate { caller, now } => {
            upgrade.activate(*caller, *now);
        }
        UpgradeOp::Cancel { caller } => {
            upgrade.cancel_pending(*caller);
        }
        UpgradeOp::Rollback { caller, now } => {
            upgrade.rollback(*caller, *now);
        }
        UpgradeOp::Finalize { caller, now } => {
            upgrade.finalize_rollback_window(*caller, *now);
        }
    }))
    .is_ok()
}

fn is_zero_contract_id(id: ContractId) -> bool {
    id.to_bytes().iter().all(|byte| *byte == 0)
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

    #[test]
    fn authorization_negative_matrix_preserves_nonce(case in auth_case_strategy()) {
        let (ok, nonce) = authorization_probe(case);
        let expected_ok = matches!(case, AuthCase::Good);
        prop_assert_eq!(ok, expected_ok, "authorization case diverged: {:?}", case);
        prop_assert_eq!(
            nonce,
            if expected_ok { 1 } else { 0 },
            "authorization case moved nonce incorrectly: {:?}",
            case,
        );
    }

    #[test]
    fn owner_set_state_matches_model_and_failed_calls_are_atomic(
        ops in prop::collection::vec(owner_set_op_strategy(), 0..120),
    ) {
        let mut owners = OwnerSet::new();
        owners.init([principal(1), principal(2)]);
        let mut model = BTreeSet::new();
        model.insert(principal(1));
        model.insert(principal(2));
        prop_assert_eq!(owners.owners(), model.iter().copied().collect::<Vec<_>>());

        for op in ops {
            let before = owners.owners();
            let expected = apply_owner_set_model(&mut model, &op);
            let actual = apply_owner_set(&mut owners, &op);
            prop_assert_eq!(actual, expected, "owner-set operation diverged: {:?}", op);
            if expected {
                prop_assert_eq!(
                    owners.owners(),
                    model.iter().copied().collect::<Vec<_>>(),
                    "successful owner-set operation left unexpected state: {:?}",
                    op,
                );
            } else {
                prop_assert_eq!(
                    owners.owners(),
                    before,
                    "failed owner-set operation mutated state: {:?}",
                    op,
                );
            }
        }
    }

    #[test]
    fn access_control_state_matches_model_and_failed_calls_are_atomic(
        ops in prop::collection::vec(access_op_strategy(), 0..140),
    ) {
        let roles = [DEFAULT_ADMIN_ROLE, role(1), role(2), role(3)];
        let accounts = all_principals();
        let admin = principal(1);
        let mut access = AccessControl::new();
        access.init_admin(admin);
        let mut model = AccessModel::new(admin);
        prop_assert_eq!(
            access_snapshot(&access, &roles, &accounts),
            model.snapshot(&roles, &accounts),
        );

        for op in ops {
            let before = access_snapshot(&access, &roles, &accounts);
            let expected = model.apply(&op);
            let actual = apply_access(&mut access, &op);
            prop_assert_eq!(actual, expected, "access-control operation diverged: {:?}", op);
            if expected {
                prop_assert_eq!(
                    access_snapshot(&access, &roles, &accounts),
                    model.snapshot(&roles, &accounts),
                    "successful access-control operation left unexpected state: {:?}",
                    op,
                );
            } else {
                prop_assert_eq!(
                    access_snapshot(&access, &roles, &accounts),
                    before,
                    "failed access-control operation mutated state: {:?}",
                    op,
                );
            }
        }
    }

    #[test]
    fn timelock_state_matches_model_and_failed_calls_are_atomic(
        ops in prop::collection::vec(timelock_op_strategy(), 0..140),
    ) {
        let ids: Vec<[u8; 32]> = (0u8..=5).map(|i| [i; 32]).collect();
        let mut timelock = Timelock::new(5);
        let mut model = TimelockModel::new(5);
        prop_assert_eq!(timelock_snapshot(&timelock, &ids), model.snapshot(&ids));

        for op in ops {
            let before = timelock_snapshot(&timelock, &ids);
            let expected = model.apply(&op);
            let actual = apply_timelock(&mut timelock, &op);
            prop_assert_eq!(actual, expected, "timelock operation diverged: {:?}", op);
            if expected {
                prop_assert_eq!(
                    timelock_snapshot(&timelock, &ids),
                    model.snapshot(&ids),
                    "successful timelock operation left unexpected state: {:?}",
                    op,
                );
            } else {
                prop_assert_eq!(
                    timelock_snapshot(&timelock, &ids),
                    before,
                    "failed timelock operation mutated state: {:?}",
                    op,
                );
            }
        }
    }

    #[test]
    fn upgrade_admin_state_matches_model_and_failed_calls_are_atomic(
        ops in prop::collection::vec(upgrade_op_strategy(), 0..120),
    ) {
        let admin = principal(1);
        let implementation = contract_id(1);
        let mut upgrade = UpgradeAdmin::new(admin, implementation, 5, 10);
        let mut model = UpgradeModel::new(admin, implementation);
        prop_assert_eq!(upgrade_snapshot(&upgrade), model.snapshot());

        for op in ops {
            let before = upgrade_snapshot(&upgrade);
            let expected = model.apply(&op);
            let actual = apply_upgrade(&mut upgrade, &op);
            prop_assert_eq!(actual, expected, "upgrade operation diverged: {:?}", op);
            if expected {
                prop_assert_eq!(
                    upgrade_snapshot(&upgrade),
                    model.snapshot(),
                    "successful upgrade operation left unexpected state: {:?}",
                    op,
                );
            } else {
                prop_assert_eq!(
                    upgrade_snapshot(&upgrade),
                    before,
                    "failed upgrade operation mutated state: {:?}",
                    op,
                );
            }
        }
    }
}
