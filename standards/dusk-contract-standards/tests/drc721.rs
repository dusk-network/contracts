// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::panic::{catch_unwind, AssertUnwindSafe};

use dusk_contract_standards::core::Principal;
use dusk_contract_standards::token::drc721::{
    ApproveCall, BalanceOf, Drc721, GetApproved, Init, InitToken,
    IsApprovedForAll, OwnerOf, RoyaltyInfo, RoyaltyRegistry,
    SetApprovalForAllCall, TokenByIndex, TokenOfOwnerByIndex, TokenUri,
    TokensOf, TransferFromCall, MAX_BASIS_POINTS, ZERO_PRINCIPAL,
};

fn p(byte: u8) -> Principal {
    Principal::phoenix([byte; 32])
}

fn assert_panics<R>(f: impl FnOnce() -> R) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}

fn init_token(initial_tokens: Vec<InitToken>) -> Drc721 {
    let mut token = Drc721::new();
    token.init(Init {
        name: "Dusk NFT".into(),
        symbol: "DNFT".into(),
        base_uri: "ipfs://collection/".into(),
        initial_tokens,
    });
    token
}

fn snapshot(
    token: &Drc721,
    accounts: &[Principal],
    token_ids: &[u64],
    approval_keys: &[(Principal, Principal)],
) -> (
    u64,
    Vec<u64>,
    Vec<Option<Principal>>,
    Vec<Principal>,
    Vec<bool>,
) {
    (
        token.total_supply(),
        accounts
            .iter()
            .map(|account| token.balance_of(BalanceOf { account: *account }))
            .collect(),
        token_ids
            .iter()
            .map(|token_id| {
                catch_unwind(AssertUnwindSafe(|| {
                    token.owner_of(OwnerOf {
                        token_id: *token_id,
                    })
                }))
                .ok()
            })
            .collect(),
        token_ids
            .iter()
            .map(|token_id| {
                catch_unwind(AssertUnwindSafe(|| {
                    token.get_approved(GetApproved {
                        token_id: *token_id,
                    })
                }))
                .unwrap_or(ZERO_PRINCIPAL)
            })
            .collect(),
        approval_keys
            .iter()
            .map(|(owner, operator)| {
                token.is_approved_for_all(IsApprovedForAll {
                    owner: *owner,
                    operator: *operator,
                })
            })
            .collect(),
    )
}

#[test]
fn drc721_init_rejects_bad_inputs_without_partial_state() {
    let owner = p(1);
    let receiver = p(2);

    let mut token = Drc721::new();
    assert_panics(|| {
        token.total_supply();
    });
    assert_panics(|| {
        token.init(Init {
            name: "Bad".into(),
            symbol: "BAD".into(),
            base_uri: String::new(),
            initial_tokens: vec![InitToken {
                account: p(0),
                token_id: 1,
            }],
        });
    });
    assert_panics(|| {
        token.total_supply();
    });

    assert_panics(|| {
        token.init(Init {
            name: "Duplicate".into(),
            symbol: "DUP".into(),
            base_uri: String::new(),
            initial_tokens: vec![
                InitToken {
                    account: owner,
                    token_id: 1,
                },
                InitToken {
                    account: receiver,
                    token_id: 1,
                },
            ],
        });
    });
    assert_panics(|| {
        token.total_supply();
    });

    let events = token.init(Init {
        name: "Recovered".into(),
        symbol: "GOOD".into(),
        base_uri: "ipfs://nft/".into(),
        initial_tokens: vec![InitToken {
            account: owner,
            token_id: 7,
        }],
    });
    assert_eq!(events.len(), 1);
    assert_eq!(token.total_supply(), 1);
    assert_eq!(token.owner_of(OwnerOf { token_id: 7 }), owner);

    assert_panics(|| {
        token.init(Init {
            name: "Again".into(),
            symbol: "AGAIN".into(),
            base_uri: String::new(),
            initial_tokens: vec![],
        });
    });
    assert_eq!(token.total_supply(), 1);
}

#[test]
fn drc721_transfer_approval_burn_and_enumeration_invariants_hold() {
    let owner = p(1);
    let receiver = p(2);
    let approved = p(3);
    let operator = p(4);

    let mut token = init_token(vec![
        InitToken {
            account: owner,
            token_id: 10,
        },
        InitToken {
            account: owner,
            token_id: 20,
        },
    ]);

    assert_eq!(token.name(), "Dusk NFT");
    assert_eq!(token.symbol(), "DNFT");
    assert_eq!(token.base_uri(), "ipfs://collection/");
    assert_eq!(
        token.token_uri(TokenUri { token_id: 10 }),
        "ipfs://collection/10"
    );
    assert_eq!(token.total_supply(), 2);
    assert_eq!(token.balance_of(BalanceOf { account: owner }), 2);
    assert_eq!(token.token_by_index(TokenByIndex { index: 0 }), 10);
    assert_eq!(token.token_by_index(TokenByIndex { index: 1 }), 20);
    assert_eq!(
        token.token_of_owner_by_index(TokenOfOwnerByIndex { owner, index: 0 }),
        10
    );
    assert_eq!(token.tokens_of(TokensOf { owner }), vec![10, 20]);

    token.approve(
        owner,
        ApproveCall {
            approved,
            token_id: 10,
        },
    );
    assert_eq!(token.get_approved(GetApproved { token_id: 10 }), approved);
    token.transfer_from(
        approved,
        TransferFromCall {
            from: owner,
            to: receiver,
            token_id: 10,
        },
    );
    assert_eq!(token.owner_of(OwnerOf { token_id: 10 }), receiver);
    assert_eq!(
        token.get_approved(GetApproved { token_id: 10 }),
        ZERO_PRINCIPAL
    );
    assert_eq!(token.balance_of(BalanceOf { account: owner }), 1);
    assert_eq!(token.balance_of(BalanceOf { account: receiver }), 1);
    assert_eq!(token.tokens_of(TokensOf { owner }), vec![20]);
    assert_eq!(token.tokens_of(TokensOf { owner: receiver }), vec![10]);

    token.set_approval_for_all(
        receiver,
        SetApprovalForAllCall {
            operator,
            approved: true,
        },
    );
    assert!(token.is_approved_for_all(IsApprovedForAll {
        owner: receiver,
        operator
    }));
    token.burn(operator, 10);
    assert_eq!(token.total_supply(), 1);
    assert_eq!(token.balance_of(BalanceOf { account: receiver }), 0);
    assert_panics(|| {
        token.owner_of(OwnerOf { token_id: 10 });
    });
    assert_eq!(token.token_by_index(TokenByIndex { index: 0 }), 20);
}

#[test]
fn drc721_failed_operations_do_not_leave_partial_state() {
    let owner = p(1);
    let receiver = p(2);
    let approved = p(3);
    let operator = p(4);
    let stranger = p(5);
    let zero = p(0);
    let accounts = [owner, receiver, approved, operator, stranger];
    let token_ids = [1, 2, 3];
    let approval_keys = [(owner, operator), (receiver, operator)];

    let mut token = init_token(vec![InitToken {
        account: owner,
        token_id: 1,
    }]);
    token.approve(
        owner,
        ApproveCall {
            approved,
            token_id: 1,
        },
    );
    token.set_approval_for_all(
        owner,
        SetApprovalForAllCall {
            operator,
            approved: true,
        },
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| {
        token.transfer_from(
            stranger,
            TransferFromCall {
                from: owner,
                to: receiver,
                token_id: 1,
            },
        );
    });
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| {
        token.transfer_from(
            approved,
            TransferFromCall {
                from: receiver,
                to: owner,
                token_id: 1,
            },
        );
    });
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| {
        token.transfer_from(
            approved,
            TransferFromCall {
                from: owner,
                to: zero,
                token_id: 1,
            },
        );
    });
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| token.mint(zero, 2));
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| token.mint(receiver, 1));
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| {
        token.approve(
            stranger,
            ApproveCall {
                approved,
                token_id: 1,
            },
        );
    });
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );

    let before = snapshot(&token, &accounts, &token_ids, &approval_keys);
    assert_panics(|| {
        token.burn(stranger, 1);
    });
    assert_eq!(
        snapshot(&token, &accounts, &token_ids, &approval_keys),
        before
    );
}

#[test]
fn drc721_royalty_registry_validates_and_quotes_without_hidden_state() {
    let default_receiver = p(1);
    let token_receiver = p(2);
    let mut royalties = RoyaltyRegistry::new();

    assert_eq!(
        royalties.royalty_info(1, 10_000),
        dusk_contract_standards::token::drc721::RoyaltyQuote {
            receiver: ZERO_PRINCIPAL,
            amount: 0,
        }
    );

    assert_panics(|| {
        royalties.set_default_royalty(RoyaltyInfo {
            receiver: p(0),
            basis_points: 1,
        });
    });
    assert_panics(|| {
        royalties.set_default_royalty(RoyaltyInfo {
            receiver: default_receiver,
            basis_points: MAX_BASIS_POINTS + 1,
        });
    });

    royalties.set_default_royalty(RoyaltyInfo {
        receiver: default_receiver,
        basis_points: 500,
    });
    assert_eq!(
        royalties.default_royalty().unwrap().receiver,
        default_receiver
    );
    assert_eq!(
        royalties.royalty_info(1, 10_000),
        dusk_contract_standards::token::drc721::RoyaltyQuote {
            receiver: default_receiver,
            amount: 500,
        }
    );

    royalties.set_token_royalty(
        1,
        RoyaltyInfo {
            receiver: token_receiver,
            basis_points: 1_250,
        },
    );
    assert_eq!(
        royalties.royalty_info(1, 8_000),
        dusk_contract_standards::token::drc721::RoyaltyQuote {
            receiver: token_receiver,
            amount: 1_000,
        }
    );
    assert_eq!(
        royalties.royalty_info(2, 8_000),
        dusk_contract_standards::token::drc721::RoyaltyQuote {
            receiver: default_receiver,
            amount: 400,
        }
    );

    royalties.clear_token_royalty(1);
    assert_eq!(royalties.royalty_info(1, 10_000).receiver, default_receiver);
    royalties.clear_default_royalty();
    assert_eq!(royalties.royalty_info(1, 10_000).receiver, ZERO_PRINCIPAL);

    royalties.set_default_royalty(RoyaltyInfo {
        receiver: default_receiver,
        basis_points: 2,
    });
    assert_panics(|| {
        royalties.royalty_info(1, u64::MAX);
    });
}

#[cfg(feature = "forge")]
#[test]
fn drc721_event_topics_are_pinned() {
    use dusk_contract_standards::token::drc721::events::{
        Approval, ApprovalForAll, DefaultRoyaltyCleared, DefaultRoyaltySet,
        TokenRoyaltyCleared, TokenRoyaltySet, Transfer, APPROVAL_FOR_ALL_TOPIC,
        APPROVAL_TOPIC, DEFAULT_ROYALTY_CLEARED_TOPIC,
        DEFAULT_ROYALTY_SET_TOPIC, TOKEN_ROYALTY_CLEARED_TOPIC,
        TOKEN_ROYALTY_SET_TOPIC, TRANSFER_TOPIC,
    };
    use dusk_forge::ContractEvent;

    assert_eq!(Transfer::TOPICS, &[TRANSFER_TOPIC]);
    assert_eq!(Approval::TOPICS, &[APPROVAL_TOPIC]);
    assert_eq!(ApprovalForAll::TOPICS, &[APPROVAL_FOR_ALL_TOPIC]);
    assert_eq!(DefaultRoyaltySet::TOPICS, &[DEFAULT_ROYALTY_SET_TOPIC]);
    assert_eq!(
        DefaultRoyaltyCleared::TOPICS,
        &[DEFAULT_ROYALTY_CLEARED_TOPIC]
    );
    assert_eq!(TokenRoyaltySet::TOPICS, &[TOKEN_ROYALTY_SET_TOPIC]);
    assert_eq!(TokenRoyaltyCleared::TOPICS, &[TOKEN_ROYALTY_CLEARED_TOPIC]);
}
