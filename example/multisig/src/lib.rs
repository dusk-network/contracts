// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! General purpose Multisignature contract.

#![no_std]
#![deny(unused_extern_crates)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::pedantic)]
#![deny(unused_crate_dependencies)]

#[cfg(target_family = "wasm")]
#[macro_use]
extern crate alloc;

#[cfg(target_family = "wasm")]
pub(crate) mod state;

#[cfg(target_family = "wasm")]
mod wasm {

    use dusk_core::abi;

    use crate::state::STATE;

    /*
     * Basic contract implementation.
     */

    #[no_mangle]
    unsafe extern "C" fn init(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |init| {
            STATE.init(init);
        })
    }

    #[no_mangle]
    unsafe extern "C" fn propose(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |args| STATE.propose(args))
    }

    #[no_mangle]
    unsafe extern "C" fn confirm(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |args| STATE.confirm(args))
    }

    /*
     * Functions to read contract state.
     */

    #[no_mangle]
    unsafe extern "C" fn admins(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.admins())
    }

    #[no_mangle]
    unsafe extern "C" fn admin_nonce(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.admin_nonce())
    }

    #[no_mangle]
    unsafe extern "C" fn admin_threshold(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.admin_threshold())
    }

    #[no_mangle]
    unsafe extern "C" fn confirmation_threshold(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.confirmation_threshold())
    }

    #[no_mangle]
    unsafe extern "C" fn proposal_ttl(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.proposal_ttl())
    }

    #[no_mangle]
    unsafe extern "C" fn tombstone_ttl(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.tombstone_ttl())
    }

    #[no_mangle]
    unsafe extern "C" fn proposal(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |id| STATE.proposal(id))
    }

    #[no_mangle]
    unsafe extern "C" fn tombstones(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.feed_tombstones())
    }

    #[no_mangle]
    unsafe extern "C" fn proposals(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |(): ()| STATE.feed_proposals())
    }

    /*
     * Functions that need the admins' approval.
     */

    #[no_mangle]
    unsafe extern "C" fn set_authority(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |args| STATE.set_authority(args))
    }

    #[no_mangle]
    unsafe extern "C" fn set_time_limits(arg_len: u32) -> u32 {
        abi::wrap_call(arg_len, |args| STATE.set_time_limits(args))
    }
}

/// Checks whether the given array contains duplicate elements.
///
/// This method is only used for small sets so an element by element comparison
/// makes sense.
#[must_use]
fn has_duplicates<T>(elements: impl AsRef<[T]>) -> bool
where
    T: PartialEq,
{
    let elements = elements.as_ref();
    let len = elements.len();
    if len > 1 {
        for i in 0..len - 1 {
            for j in i + 1..len {
                if elements[i] == elements[j] {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_duplicates() {
        // test sets without duplicates
        let empty: [u32; 0] = [];
        assert!(!has_duplicates(empty));
        assert!(!has_duplicates([1]));
        assert!(!has_duplicates([1, 2, 3]));
        assert!(!has_duplicates([1, 2, 3, 4, 5]));

        // test sets with duplicates
        assert!(has_duplicates([1, 1]));
        assert!(has_duplicates([1, 2, 2]));
        assert!(has_duplicates([1, 1, 2, 3]));
        assert!(has_duplicates([1, 2, 3, 3]));
        assert!(has_duplicates([1, 2, 2, 3]));
        assert!(has_duplicates([1, 2, 3, 3, 4, 5]));
    }
}
