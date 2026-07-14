//! subscription-logic: the schedule law of the game, and nothing else.
//!
//! Zero dependencies. Time is an argument, never a system call; addresses,
//! hashes and signatures do not exist at this altitude — the schedule is
//! pure numbers (docs/game-spec.md §4).

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
