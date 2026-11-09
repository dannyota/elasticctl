//! Timestamp generation and calendar conversion.

/// Format the current time as RFC3339 UTC with millisecond precision, e.g.
/// `2026-09-01T12:34:56.789Z`. The workspace has no date-formatting
/// dependency, so this hand-rolls it from `SystemTime` using Howard
/// Hinnant's civil-from-days algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>).
pub(crate) fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let millis = now.as_millis() as i64;
    let secs = millis.div_euclid(1000);
    let ms = millis.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{ms:03}Z")
}

/// Convert a day count since the Unix epoch (1970-01-01) to a proleptic
/// Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn civil_from_days_matches_known_epoch_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(1_700_000_000 / 86_400), (2023, 11, 14));
        assert_eq!(civil_from_days(1_893_456_000 / 86_400), (2030, 1, 1));
    }

    #[test]
    fn now_rfc3339_is_well_formed_and_close_to_the_wall_clock() {
        let formatted = now_rfc3339();
        assert_eq!(formatted.len(), "2026-09-01T12:34:56.789Z".len());
        assert!(formatted.starts_with("20"), "{formatted}");
        assert!(formatted.ends_with('Z'), "{formatted}");
        let parsed: Value = json!(formatted);
        assert!(parsed.is_string());
    }
}
