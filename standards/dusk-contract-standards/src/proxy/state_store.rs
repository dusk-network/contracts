// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Proxy-owned state store.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Key-value state store for proxy-owned implementation state.
#[derive(Clone, Debug, Default)]
pub struct StateStore {
    words: BTreeMap<[u8; 32], [u8; 32]>,
    bytes: BTreeMap<[u8; 32], Vec<u8>>,
    namespaced_words: BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
    namespaced_bytes: BTreeMap<([u8; 32], [u8; 32]), Vec<u8>>,
}

impl StateStore {
    /// Creates empty state.
    pub const fn new() -> Self {
        Self {
            words: BTreeMap::new(),
            bytes: BTreeMap::new(),
            namespaced_words: BTreeMap::new(),
            namespaced_bytes: BTreeMap::new(),
        }
    }

    /// Reads a word.
    pub fn get_word(&self, key: [u8; 32]) -> [u8; 32] {
        self.words.get(&key).copied().unwrap_or([0u8; 32])
    }

    /// Writes a word.
    pub fn set_word(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.words.insert(key, value);
    }

    /// Reads bytes.
    pub fn get_bytes(&self, key: [u8; 32]) -> Vec<u8> {
        self.bytes.get(&key).cloned().unwrap_or_default()
    }

    /// Writes bytes.
    pub fn set_bytes(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.bytes.insert(key, value);
    }

    /// Reads a namespaced word.
    pub fn get_namespaced_word(
        &self,
        namespace: [u8; 32],
        key: [u8; 32],
    ) -> [u8; 32] {
        self.namespaced_words
            .get(&(namespace, key))
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Writes a namespaced word.
    pub fn set_namespaced_word(
        &mut self,
        namespace: [u8; 32],
        key: [u8; 32],
        value: [u8; 32],
    ) {
        self.namespaced_words.insert((namespace, key), value);
    }

    /// Reads namespaced bytes.
    pub fn get_namespaced_bytes(
        &self,
        namespace: [u8; 32],
        key: [u8; 32],
    ) -> Vec<u8> {
        self.namespaced_bytes
            .get(&(namespace, key))
            .cloned()
            .unwrap_or_default()
    }

    /// Writes namespaced bytes.
    pub fn set_namespaced_bytes(
        &mut self,
        namespace: [u8; 32],
        key: [u8; 32],
        value: Vec<u8>,
    ) {
        self.namespaced_bytes.insert((namespace, key), value);
    }

    /// Deletes a key from both stores.
    pub fn delete(&mut self, key: [u8; 32]) {
        self.words.remove(&key);
        self.bytes.remove(&key);
    }

    /// Deletes a key from both namespaced stores.
    pub fn delete_namespaced(&mut self, namespace: [u8; 32], key: [u8; 32]) {
        self.namespaced_words.remove(&(namespace, key));
        self.namespaced_bytes.remove(&(namespace, key));
    }
}
