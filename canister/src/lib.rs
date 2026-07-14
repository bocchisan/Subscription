//! subscription: the stateless resolver canister of prepaid streams
//! (docs/game-spec.md).
//!
//! No records, no timers, no stable memory: both rules of the game are pure
//! functions of the presented arguments, the clock and the derivation path.
//! The update surface is frozen by the .did allowlist lint. There is nothing
//! to migrate on upgrade — and that is a property, not an accident.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

pub mod api;
pub mod auth;
pub mod sign;

/// One chain the game serves; baked from config/ at build time.
pub struct ChainSpec {
    pub id: &'static str,
    /// Program id of the deployed stream shape — the factory of every escrow
    /// this canister resolves.
    pub factory: &'static str,
    /// Cluster-scoped domain, the head of every signed message.
    pub domain: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/profile.rs"));

/// The clock of the law (docs/game-spec.md §4): seconds, as the schedule
/// arithmetic of the logic crate counts them.
pub(crate) fn now_seconds() -> i64 {
    i64::try_from(ic_cdk::api::time() / 1_000_000_000).unwrap_or(i64::MAX)
}

/// A canister with a malformed config must not exist; there is no state to
/// preserve, so both lifecycle hooks only validate.
#[ic_cdk::init]
fn init() {
    if let Err(error) = auth::validate_config() {
        ic_cdk::trap(error.text());
    }
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    if let Err(error) = auth::validate_config() {
        ic_cdk::trap(error.text());
    }
}
