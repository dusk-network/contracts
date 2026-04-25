//! Emergency stop primitive.

use crate::core::error;

/// Pausable module.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pausable {
    paused: bool,
}

impl Pausable {
    /// Creates an unpaused module.
    pub const fn new() -> Self {
        Self { paused: false }
    }

    /// Returns whether the module is paused.
    pub const fn paused(&self) -> bool {
        self.paused
    }

    /// Panics when paused.
    pub fn assert_not_paused(&self) {
        if self.paused {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    /// Panics when not paused.
    pub fn assert_paused(&self) {
        if !self.paused {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    /// Pauses.
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Unpauses.
    pub fn unpause(&mut self) {
        self.paused = false;
    }
}
