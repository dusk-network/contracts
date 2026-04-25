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
