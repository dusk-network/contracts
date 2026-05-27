// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Reentrancy guard.

/// Reentrancy guard module.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

    /// Enters the guarded section.
    pub fn enter(&mut self) {
        if self.entered {
            panic!("ReentrancyGuard: reentrant call");
        }
        self.entered = true;
    }

    /// Exits the guarded section.
    pub fn exit(&mut self) {
        self.entered = false;
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
