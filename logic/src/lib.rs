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

pub mod schedule;

/// Version of the law. The rules of this game are two pure functions; if
/// they ever change, that is a different game — so this is pinned by a test
/// and expected to stay at 1 forever.
pub const LOGIC_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    #[test]
    fn logic_version_is_pinned() {
        assert_eq!(super::LOGIC_VERSION, 1);
    }
}
