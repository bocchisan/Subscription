//! The schedule law (docs/game-spec.md §4): chunk `index` becomes due at
//! `t0 + index·period`, and a release may be signed only at or after that
//! moment. The arithmetic mirrors the deployed shape's `due_at` exactly:
//! overflow is an error value, never a wrap and never a panic. The order of
//! chunks is not this crate's business — the onchain form holds it.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    /// The due time does not fit the clock's integer range.
    Overflow,
    /// The chunk's due time has not arrived yet.
    NotDue,
}

/// When chunk `index` becomes due: `t0 + index·period`. `None` when the sum
/// leaves the i64 range — the same totality the deployed shape has.
pub fn due_at(t0: i64, period: i64, index: u16) -> Option<i64> {
    t0.checked_add(i64::from(index).checked_mul(period)?)
}

/// The single law of the game: a release for chunk `index` is signable
/// iff `now` has reached the chunk's due time.
pub fn release_due(now: i64, t0: i64, period: i64, index: u16) -> Result<(), ScheduleError> {
    let due = due_at(t0, period, index).ok_or(ScheduleError::Overflow)?;
    if now >= due {
        Ok(())
    } else {
        Err(ScheduleError::NotDue)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // Exact fixtures, mirroring the deployed shape's own unit vectors.
    #[test]
    fn due_time_is_exact() {
        assert_eq!(due_at(1_000, 60, 0), Some(1_000));
        assert_eq!(due_at(1_000, 60, 3), Some(1_180));
        assert_eq!(due_at(-100, 60, 2), Some(20));
        assert_eq!(due_at(i64::MAX, 1, 1), None);
    }

    #[test]
    fn law_boundaries_are_inclusive() {
        assert_eq!(release_due(999, 1_000, 60, 0), Err(ScheduleError::NotDue));
        assert_eq!(release_due(1_000, 1_000, 60, 0), Ok(()));
        assert_eq!(release_due(1_179, 1_000, 60, 3), Err(ScheduleError::NotDue));
        assert_eq!(release_due(1_180, 1_000, 60, 3), Ok(()));
        assert_eq!(
            release_due(i64::MAX, i64::MAX, 1, 1),
            Err(ScheduleError::Overflow)
        );
    }

    proptest! {
        // Parity: due_at equals the wide (i128) computation whenever that
        // fits i64, and is None exactly when it does not.
        #[test]
        fn due_at_matches_wide_arithmetic(t0: i64, period: i64, index: u16) {
            let wide = i128::from(t0) + i128::from(index) * i128::from(period);
            let expected = i64::try_from(wide).ok();
            prop_assert_eq!(due_at(t0, period, index), expected);
        }

        // The law is exactly `now ≥ due`: Ok at and after the due time,
        // NotDue before it, Overflow when the due time does not exist.
        #[test]
        fn law_is_now_at_least_due(now: i64, t0: i64, period: i64, index: u16) {
            let got = release_due(now, t0, period, index);
            match due_at(t0, period, index) {
                None => prop_assert_eq!(got, Err(ScheduleError::Overflow)),
                Some(due) if now >= due => prop_assert_eq!(got, Ok(())),
                Some(_) => prop_assert_eq!(got, Err(ScheduleError::NotDue)),
            }
        }

        // Monotone in time: a due chunk never becomes not-due as the clock
        // moves forward.
        #[test]
        fn due_is_monotone_in_time(now: i64, later_by in 0i64..=1_000_000, t0: i64, period: i64, index: u16) {
            if release_due(now, t0, period, index).is_ok() {
                let later = now.saturating_add(later_by);
                prop_assert_eq!(release_due(later, t0, period, index), Ok(()));
            }
        }

        // Strictly increasing in index for a positive period: the next
        // chunk is due exactly one period later.
        #[test]
        fn due_times_step_by_one_period(t0: i64, period in 1i64..=i64::MAX, index in 0u16..u16::MAX) {
            if let (Some(due), Some(next)) =
                (due_at(t0, period, index), due_at(t0, period, index + 1))
            {
                prop_assert_eq!(i128::from(next) - i128::from(due), i128::from(period));
                prop_assert!(next > due);
            }
        }

        // Determinism: one input, bitwise one result.
        #[test]
        fn law_is_deterministic(now: i64, t0: i64, period: i64, index: u16) {
            prop_assert_eq!(
                release_due(now, t0, period, index),
                release_due(now, t0, period, index)
            );
        }
    }
}
