use super::*;

fn bounds() -> LocalValidityBounds {
    LocalValidityBounds {
        request_start: 2_000,
        request_end: 10_500,
        assertion_start: 1_000,
        assertion_end: 20_500,
        outgoing_start: 2,
        outgoing_end: 30,
    }
}
#[test]
fn original_wall_window_accepts_only_inside_exact_milliseconds() {
    assert!(require_local_window(2, 2_000, 2_000, bounds()).is_ok());
    assert!(require_local_window(10, 2_000, 10_499, bounds()).is_ok());
    assert!(matches!(
        require_local_window(10, 2_000, 10_500, bounds()),
        Err(TransportError::InvalidTime)
    ));
    assert!(require_local_window(1, 1_000, 1_999, bounds()).is_err());
}
#[test]
fn assertion_and_outgoing_expiries_remain_independent() {
    let mut b = bounds();
    b.assertion_end = 3_500;
    assert!(require_local_window(3, 2_000, 3_500, b).is_err());
    let mut b = bounds();
    b.assertion_start = 3_500;
    assert!(require_local_window(3, 2_000, 3_499, b).is_err());
    let mut b = bounds();
    b.outgoing_end = 3;
    assert!(require_local_window(3, 2_000, 3_000, b).is_err());
    let mut b = bounds();
    b.outgoing_start = 3;
    assert!(require_local_window(2, 2_000, 2_999, b).is_err());
}
#[test]
fn rollback_is_rejected_even_within_one_timestamp_second() {
    assert!(require_local_window(2, 2_999, 2_999, bounds()).is_ok());
    assert!(require_local_window(2, 2_999, 2_998, bounds()).is_err());
    assert!(require_local_window(2, 3_000, 2_999, bounds()).is_err());
}

#[test]
fn retained_monotonic_duration_uses_earliest_original_expiry() {
    assert_eq!(
        remaining_original_window_ms(1_000, 6_000, 8_000, 9),
        Ok(5_000)
    );
    assert_eq!(
        remaining_original_window_ms(1_000, 8_000, 6_000, 9),
        Ok(5_000)
    );
    assert_eq!(
        remaining_original_window_ms(1_000, 8_000, 9_000, 6),
        Ok(5_000)
    );
    assert!(remaining_original_window_ms(6_000, 6_000, 8_000, 9).is_err());
    assert!(remaining_original_window_ms(6_001, 6_000, 8_000, 9).is_err());
    assert!(remaining_original_window_ms(1_000, 6_000, 8_000, -1).is_err());
    assert!(remaining_original_window_ms(1_000, 6_000, 8_000, i64::MAX).is_err());
}
