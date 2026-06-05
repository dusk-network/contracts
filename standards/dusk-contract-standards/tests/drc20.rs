// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::core::Principal;
use dusk_contract_standards::token::drc20::{
    Allowance, ApproveCall, BalanceOf, Checkpoint, Checkpoints,
    DecreaseAllowanceCall, Drc20, IncreaseAllowanceCall, Init, InitBalance,
    SupplyCap, TransferCall, TransferFromCall, VotingUnits,
};

fn p(byte: u8) -> Principal {
    Principal::phoenix([byte; 32])
}

fn assert_panics<R>(f: impl FnOnce() -> R) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}

fn assert_rkyv_roundtrip<T>(value: T)
where
    T: rkyv::Archive
        + rkyv::Serialize<rkyv::ser::serializers::AllocSerializer<1024>>
        + PartialEq
        + core::fmt::Debug,
    T::Archived:
        rkyv::Deserialize<T, rkyv::de::deserializers::SharedDeserializeMap>,
{
    let bytes = rkyv::to_bytes::<_, 1024>(&value).unwrap();
    let decoded = unsafe { rkyv::from_bytes_unchecked::<T>(&bytes) }.unwrap();
    assert_eq!(decoded, value);
}

fn init_token(initial_balances: Vec<InitBalance>) -> Drc20 {
    let mut token = Drc20::new();
    token.init(Init {
        name: "Dusk Token".into(),
        symbol: "DUSKX".into(),
        decimals: 9,
        initial_balances,
    });
    token
}

fn balance_sum(token: &Drc20, accounts: &[Principal]) -> u64 {
    accounts
        .iter()
        .map(|account| token.balance_of(BalanceOf { account: *account }))
        .sum()
}

fn snapshot(
    token: &Drc20,
    accounts: &[Principal],
    allowances: &[(Principal, Principal)],
) -> (u64, Vec<u64>, Vec<u64>) {
    (
        token.total_supply(),
        accounts
            .iter()
            .map(|account| token.balance_of(BalanceOf { account: *account }))
            .collect(),
        allowances
            .iter()
            .map(|(owner, spender)| {
                token.allowance(Allowance {
                    owner: *owner,
                    spender: *spender,
                })
            })
            .collect(),
    )
}

#[test]
fn checkpoints_overwrite_same_key_instead_of_appending() {
    let mut checkpoints = Checkpoints::new();

    checkpoints.push(10, 100);
    checkpoints.push(10, 75);

    assert_eq!(checkpoints.latest(), 75);
    assert_eq!(checkpoints.get_at(9), 0);
    assert_eq!(checkpoints.get_at(10), 75);
    assert_eq!(checkpoints.get_at(11), 75);
    assert_eq!(checkpoints.entries(), &[Checkpoint { key: 10, value: 75 }]);

    checkpoints.push(11, 80);
    assert_eq!(
        checkpoints.entries(),
        &[
            Checkpoint { key: 10, value: 75 },
            Checkpoint { key: 11, value: 80 },
        ]
    );
}

#[test]
fn drc20_init_rejects_bad_inputs_without_partial_state() {
    let owner = p(1);
    let receiver = p(2);

    let mut token = Drc20::new();
    assert_panics(|| {
        token.total_supply();
    });
    assert_panics(|| {
        token.init(Init {
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
        token.total_supply();
    });

    let events = token.init(Init {
        name: "Recovered".into(),
        symbol: "GOOD".into(),
        decimals: 9,
        initial_balances: vec![
            InitBalance {
                account: owner,
                amount: 10,
            },
            InitBalance {
                account: receiver,
                amount: 0,
            },
        ],
    });
    assert_eq!(events.len(), 1);
    assert_eq!(token.total_supply(), 10);
    assert_eq!(token.balance_of(BalanceOf { account: owner }), 10);
    assert_eq!(token.balance_of(BalanceOf { account: receiver }), 0);

    assert_panics(|| {
        token.init(Init {
            name: "Again".into(),
            symbol: "AGAIN".into(),
            decimals: 9,
            initial_balances: vec![],
        });
    });
    assert_eq!(token.total_supply(), 10);

    let mut overflowing = Drc20::new();
    assert_panics(|| {
        overflowing.init(Init {
            name: "Overflow".into(),
            symbol: "OVR".into(),
            decimals: 9,
            initial_balances: vec![
                InitBalance {
                    account: owner,
                    amount: u64::MAX,
                },
                InitBalance {
                    account: receiver,
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
fn drc20_transfer_allowance_mint_and_burn_preserve_supply_invariant() {
    let owner = p(1);
    let receiver = p(2);
    let spender = p(3);
    let accounts = [owner, receiver, spender];

    let mut token = init_token(vec![InitBalance {
        account: owner,
        amount: 100,
    }]);
    assert_eq!(token.name(), "Dusk Token");
    assert_eq!(token.symbol(), "DUSKX");
    assert_eq!(token.decimals(), 9);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));

    let transfer = token.transfer(
        owner,
        TransferCall {
            to: receiver,
            amount: 40,
        },
    );
    assert_eq!(transfer.from, owner);
    assert_eq!(transfer.to, receiver);
    assert_eq!(transfer.amount, 40);
    assert_eq!(token.total_supply(), 100);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));

    let approval = token.approve(
        receiver,
        ApproveCall {
            spender,
            amount: 15,
        },
    );
    assert_eq!(approval.owner, receiver);
    assert_eq!(approval.spender, spender);
    assert_eq!(approval.amount, 15);
    assert_eq!(
        token.allowance(Allowance {
            owner: receiver,
            spender
        }),
        15
    );

    assert_eq!(
        token
            .increase_allowance(
                receiver,
                IncreaseAllowanceCall {
                    spender,
                    added_amount: 5,
                },
            )
            .amount,
        20
    );
    assert_eq!(
        token
            .decrease_allowance(
                receiver,
                DecreaseAllowanceCall {
                    spender,
                    subtracted_amount: 5,
                },
            )
            .amount,
        15
    );

    let transfer = token.transfer_from(
        spender,
        TransferFromCall {
            owner: receiver,
            to: owner,
            amount: 10,
        },
    );
    assert_eq!(transfer.from, receiver);
    assert_eq!(transfer.to, owner);
    assert_eq!(transfer.amount, 10);
    assert_eq!(
        token.allowance(Allowance {
            owner: receiver,
            spender
        }),
        5
    );
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));

    token.mint(spender, 25);
    assert_eq!(token.total_supply(), 125);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));
    token.burn(spender, 5);
    assert_eq!(token.total_supply(), 120);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));
}

#[test]
fn drc20_failed_operations_do_not_mutate_balances_supply_or_allowances() {
    let owner = p(1);
    let receiver = p(2);
    let spender = p(3);
    let zero = p(0);
    let accounts = [owner, receiver, spender];
    let allowance_keys = [(owner, spender), (receiver, spender)];

    let mut token = init_token(vec![InitBalance {
        account: owner,
        amount: 10,
    }]);
    token.approve(owner, ApproveCall { spender, amount: 7 });

    let before = snapshot(&token, &accounts, &allowance_keys);
    assert_panics(|| {
        token.transfer(
            owner,
            TransferCall {
                to: zero,
                amount: 3,
            },
        );
    });
    assert_eq!(snapshot(&token, &accounts, &allowance_keys), before);

    let before = snapshot(&token, &accounts, &allowance_keys);
    assert_panics(|| {
        token.transfer(
            receiver,
            TransferCall {
                to: owner,
                amount: 1,
            },
        );
    });
    assert_eq!(snapshot(&token, &accounts, &allowance_keys), before);

    let before = snapshot(&token, &accounts, &allowance_keys);
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
    assert_eq!(snapshot(&token, &accounts, &allowance_keys), before);

    let before = snapshot(&token, &accounts, &allowance_keys);
    assert_panics(|| {
        token.transfer_from(
            spender,
            TransferFromCall {
                owner,
                to: receiver,
                amount: 8,
            },
        );
    });
    assert_eq!(snapshot(&token, &accounts, &allowance_keys), before);

    token.approve_for(receiver, ApproveCall { spender, amount: 5 });
    let before = snapshot(&token, &accounts, &allowance_keys);
    assert_panics(|| {
        token.transfer_from(
            spender,
            TransferFromCall {
                owner: receiver,
                to: owner,
                amount: 1,
            },
        );
    });
    assert_eq!(snapshot(&token, &accounts, &allowance_keys), before);

    let before = snapshot(&token, &accounts, &allowance_keys);
    assert_panics(|| {
        token.decrease_allowance(
            owner,
            DecreaseAllowanceCall {
                spender,
                subtracted_amount: 8,
            },
        );
    });
    assert_eq!(snapshot(&token, &accounts, &allowance_keys), before);
}

#[test]
fn drc20_self_and_zero_amount_operations_do_not_break_accounting() {
    let owner = p(1);
    let receiver = p(2);
    let accounts = [owner, receiver];
    let mut token = init_token(vec![InitBalance {
        account: owner,
        amount: 50,
    }]);

    token.transfer(
        owner,
        TransferCall {
            to: owner,
            amount: 10,
        },
    );
    assert_eq!(token.balance_of(BalanceOf { account: owner }), 50);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));

    token.transfer(
        owner,
        TransferCall {
            to: receiver,
            amount: 0,
        },
    );
    assert_eq!(token.balance_of(BalanceOf { account: owner }), 50);
    assert_eq!(token.balance_of(BalanceOf { account: receiver }), 0);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));

    token.mint(receiver, 0);
    token.burn(owner, 0);
    assert_eq!(token.total_supply(), 50);
    assert_eq!(token.total_supply(), balance_sum(&token, &accounts));
}

#[test]
fn drc20_rejects_overflow_without_partial_state() {
    let owner = p(1);
    let receiver = p(2);
    let accounts = [owner, receiver];
    let mut token = init_token(vec![InitBalance {
        account: owner,
        amount: u64::MAX,
    }]);

    let before = snapshot(&token, &accounts, &[]);
    assert_panics(|| token.mint(receiver, 1));
    assert_eq!(snapshot(&token, &accounts, &[]), before);
}

#[test]
fn drc20_supply_cap_and_voting_units_pin_policy_hooks() {
    let owner = p(1);
    let receiver = p(2);

    let mut cap = SupplyCap::new(100);
    cap.assert_mint(90, 10);
    assert_eq!(cap.remaining(40), 60);
    assert_eq!(cap.remaining(120), 0);
    assert_panics(|| cap.assert_mint(90, 11));
    assert_panics(|| cap.assert_mint(u64::MAX, 1));
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

    let before_owner = votes.latest_votes(owner);
    let before_receiver = votes.latest_votes(receiver);
    let before_total = votes.latest_total_supply();
    assert_panics(|| votes.move_units(Some(receiver), None, 100, 13));
    assert_eq!(votes.latest_votes(owner), before_owner);
    assert_eq!(votes.latest_votes(receiver), before_receiver);
    assert_eq!(votes.latest_total_supply(), before_total);
    assert_panics(|| votes.write_votes(owner, 9, 1));
}

#[cfg(feature = "forge")]
#[test]
fn drc20_event_topics_are_pinned() {
    use dusk_contract_standards::token::drc20::events::{
        Approval, Transfer, APPROVAL_TOPIC, TRANSFER_TOPIC,
    };
    use dusk_forge::ContractEvent;

    assert_eq!(Transfer::TOPICS, &[TRANSFER_TOPIC]);
    assert_eq!(Approval::TOPICS, &[APPROVAL_TOPIC]);
}

#[test]
fn drc20_events_roundtrip_with_rkyv() {
    use dusk_contract_standards::token::drc20::events::{Approval, Transfer};

    let owner = p(11);
    let spender = p(12);
    let receiver = p(13);

    assert_rkyv_roundtrip(Transfer {
        from: owner,
        to: receiver,
        amount: 123,
    });
    assert_rkyv_roundtrip(Approval {
        owner,
        spender,
        amount: 456,
    });
    assert!(rkyv::check_archived_root::<Transfer>(&[0u8]).is_err());
    assert!(rkyv::check_archived_root::<Approval>(&[0u8]).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn drc20_events_roundtrip_with_serde_json() {
    use dusk_contract_standards::token::drc20::events::{Approval, Transfer};

    let owner = p(21);
    let spender = p(22);
    let receiver = p(23);

    let transfer = Transfer {
        from: owner,
        to: receiver,
        amount: 321,
    };
    let json = serde_json::to_string(&transfer).unwrap();
    let decoded: Transfer = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, transfer);

    let approval = Approval {
        owner,
        spender,
        amount: 654,
    };
    let json = serde_json::to_string(&approval).unwrap();
    let decoded: Approval = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, approval);

    assert!(serde_json::from_str::<Transfer>(r#"{"from":[]}"#).is_err());
    assert!(serde_json::from_str::<Approval>(r#"{"owner":[]}"#).is_err());
}
