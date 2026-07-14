//! subscription: the stateless resolver canister of prepaid streams.
//!
//! No records, no timers, no stable memory: both rules of the game
//! (docs/game-spec.md §4) are pure functions of the presented arguments,
//! the clock and the derivation path. Grows strictly by build-plan stages:
//! G2 adds get_resolver + request_release, G3 adds request_cancel.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
