//! `SimpleDateFormat` of the patterns the original's plugins use, in a zone of a fixed
//! offset (the host's `local_time` gives the system's).

/// The civil date of `days` since 1970-01-01: (year, month 1–12, day 1–31).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The week-based year (`YYYY`) of a day, with weeks from Monday and week 1 the one holding
/// January 1 (`GregorianCalendar` of the Russian and Kazakh locales): the last days of
/// December in the week of the next January 1 belong to the next year.
fn week_year(days: i64) -> i64 {
    let (year, _, _) = civil(days);
    // Monday of this day's week (1970-01-01 was a Thursday).
    let monday = days - (days + 3).rem_euclid(7);
    let next_new_year = days_from_civil(year + 1, 1, 1);
    if monday + 6 >= next_new_year {
        year + 1
    } else {
        year
    }
}

/// `new SimpleDateFormat(pattern).format(date)` in a zone `offset_seconds` from UTC.
/// Letters: `y` (year), `Y` (week year), `M` (month number), `d`, `H`, `m`, `s`, `S`
/// (milliseconds), `Z` (`+0500`); text in single quotes (`''` a quote) and other characters as
/// they are. A run of one letter pads to its length (`yy` is the last two digits).
///
/// # Panics
///
/// On a letter outside these (a port's pattern is a constant).
pub fn format_java(pattern: &str, unix_ms: i64, offset_seconds: i32) -> String {
    let local_ms = unix_ms + i64::from(offset_seconds) * 1000;
    let days = local_ms.div_euclid(86_400_000);
    let ms_of_day = local_ms.rem_euclid(86_400_000);
    let (year, month, day) = civil(days);
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if chars.get(i + 1) == Some(&'\'') {
                out.push('\'');
                i += 2;
                continue;
            }
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) != Some(&'\'') {
                        break;
                    }
                    i += 1;
                }
                out.push(chars[i]);
                i += 1;
            }
            i += 1;
            continue;
        }
        if !c.is_ascii_alphabetic() {
            out.push(c);
            i += 1;
            continue;
        }
        let mut n = 1;
        while chars.get(i + n) == Some(&c) {
            n += 1;
        }
        let pad = |v: i64| format!("{v:0n$}");
        let year_text = |y: i64| {
            if n == 2 {
                format!("{:02}", y.rem_euclid(100))
            } else {
                pad(y)
            }
        };
        out.push_str(&match c {
            'y' => year_text(year),
            'Y' => year_text(week_year(days)),
            'M' => pad(i64::from(month)),
            'd' => pad(i64::from(day)),
            'H' => pad(ms_of_day / 3_600_000),
            'm' => pad(ms_of_day / 60_000 % 60),
            's' => pad(ms_of_day / 1000 % 60),
            'S' => pad(ms_of_day % 1000),
            'Z' => {
                let sign = if offset_seconds < 0 { '-' } else { '+' };
                let minutes = offset_seconds.unsigned_abs() / 60;
                format!("{sign}{:02}{:02}", minutes / 60, minutes % 60)
            }
            other => panic!("pattern letter {other} is not supported"),
        });
        i += n;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::format_java;

    /// 2024-03-01 10:15:00.007 at +05:00.
    const T: i64 = 1_709_270_100_007;

    #[test]
    fn java_date_patterns() {
        let almaty = 5 * 3600;
        assert_eq!(format_java("dd.MM.yyyy", T, almaty), "01.03.2024");
        assert_eq!(
            format_java("dd/MM/yyyy HH:mm:ss", T, almaty),
            "01/03/2024 10:15:00"
        );
        assert_eq!(
            format_java("dd-MM-yyyy HH:mm:ss Z", T, almaty),
            "01-03-2024 10:15:00 +0500"
        );
        assert_eq!(
            format_java("yyyy-MM-dd'T'HH:mm:ss.SSSZ", T, almaty),
            "2024-03-01T10:15:00.007+0500"
        );
        assert_eq!(
            format_java("dd-MM-yyyy HH:mm:ss Z", T, -3 * 3600 - 1800),
            "01-03-2024 01:45:00 -0330"
        );
        assert_eq!(format_java("'it''s' yy", T, 0), "it's 24");
    }

    #[test]
    fn week_year_in_the_last_days_of_december() {
        // 2024-12-30 (a Monday) is in the week of 2025-01-01.
        let dec30 = 1_735_516_800_000;
        assert_eq!(format_java("dd.MM.YYYY", dec30, 0), "30.12.2025");
        assert_eq!(format_java("dd.MM.yyyy", dec30, 0), "30.12.2024");
        // 2024-12-29 (a Sunday) is not.
        assert_eq!(
            format_java("dd.MM.YYYY", dec30 - 86_400_000, 0),
            "29.12.2024"
        );
        // 2021-01-01 (a Friday) is week 1 of 2021 with Monday weeks and one minimal day.
        assert_eq!(
            format_java("dd.MM.YYYY", 1_609_459_200_000, 0),
            "01.01.2021"
        );
    }
}
