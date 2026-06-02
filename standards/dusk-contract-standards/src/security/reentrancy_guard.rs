// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Reentrancy guard.

use crate::core::error;

/// Reentrancy guard module.
///
/// The guard is intentionally not `Copy` or `Clone`: locking a detached copy
/// would not protect the stored guard.
///
/// ```compile_fail
/// use dusk_contract_standards::security::ReentrancyGuard;
///
/// let guard = ReentrancyGuard::new();
/// let copied = guard;
/// let _used_after_move = guard;
/// let _ = copied;
/// ```
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReentrancyGuard {
    entered: bool,
}

/// Active reentrancy lock.
///
/// Dropping the lock exits the guarded section. This keeps native tests and
/// non-aborting hosts from leaving the guard stuck when a guarded closure
/// panics.
#[derive(Debug)]
pub struct ReentrancyLock<'a> {
    entered: &'a mut bool,
}

impl ReentrancyGuard {
    /// Creates a new guard.
    pub const fn new() -> Self {
        Self { entered: false }
    }

    /// Returns whether the guard is currently entered.
    pub const fn entered(&self) -> bool {
        self.entered
    }

    fn enter(&mut self) {
        if self.entered {
            panic!("{}", error::REENTRANCY);
        }
        self.entered = true;
    }

    /// Enters the guarded section and returns an RAII lock.
    pub fn lock(&mut self) -> ReentrancyLock<'_> {
        self.enter();
        ReentrancyLock {
            entered: &mut self.entered,
        }
    }

    /// Runs a closure in a guarded section.
    pub fn run<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let _lock = self.lock();
        f()
    }
}

impl Drop for ReentrancyLock<'_> {
    fn drop(&mut self) {
        *self.entered = false;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;

    #[test]
    fn enter_rejects_reentry() {
        let mut guard = ReentrancyGuard::new();
        guard.enter();
        assert!(guard.entered());
        assert!(catch_unwind(AssertUnwindSafe(|| guard.enter())).is_err());
        assert!(guard.entered());
    }

    #[test]
    fn lock_resets_after_panic() {
        let mut guard = ReentrancyGuard::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _lock = guard.lock();
            panic!("boom");
        }));
        assert!(result.is_err());
        assert!(!guard.entered());
        guard.run(|| {});
        assert!(!guard.entered());
    }
}
