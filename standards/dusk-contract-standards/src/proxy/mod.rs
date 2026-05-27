// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Dusk-native proxy and upgrade primitives.

pub mod state_store;
pub mod upgrade;

pub use state_store::StateStore;
pub use upgrade::{
    PendingUpgrade, RollbackFinalized, UpgradeActivated, UpgradeAdmin,
    UpgradeCancelled, UpgradePrepared, UpgradeRolledBack,
    ROLLBACK_FINALIZED_TOPIC, UPGRADE_ACTIVATED_TOPIC, UPGRADE_CANCELLED_TOPIC,
    UPGRADE_PREPARED_TOPIC, UPGRADE_ROLLED_BACK_TOPIC,
};
