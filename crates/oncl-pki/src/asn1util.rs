//! DER pieces shared by the protocol modules (time-stamping, OCSP, CRL): values of a fixed
//! tag kept raw, small `ENUMERATED` values, unsigned INTEGER bytes and `GeneralizedTime`
//! with fractions of a second.

use der::{DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Tag, Writer};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// A value of a fixed tag kept as its raw contents.
macro_rules! raw_value {
    ($(#[$doc:meta])* $name:ident, $tag:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name<'a>(pub &'a [u8]);

        impl<'a> DecodeValue<'a> for $name<'a> {
            type Error = der::Error;

            fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
                reader.read_slice(header.length()).map($name)
            }
        }

        impl EncodeValue for $name<'_> {
            fn value_len(&self) -> der::Result<Length> {
                Length::try_from(self.0.len())
            }

            fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
                writer.write(self.0)
            }
        }

        impl FixedTag for $name<'_> {
            const TAG: Tag = $tag;
        }
    };
}

raw_value!(
    /// Contents of a `SEQUENCE` (or of an `IMPLICIT` tagged one), raw.
    RawSequence,
    Tag::Sequence
);
raw_value!(
    /// Contents of a `GeneralizedTime`, raw: RFC 3161 allows fractions of a second in
    /// genTime, which `der::asn1::GeneralizedTime` refuses. Read with [`generalized_time`].
    RawGeneralizedTime,
    Tag::GeneralizedTime
);

/// An `ENUMERATED` of 0 to 127: `OCSPResponseStatus` and `CRLReason` have no larger value,
/// anything else is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Enumerated(pub u8);

impl<'a> DecodeValue<'a> for Enumerated {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        match reader.read_slice(header.length())? {
            &[value] if value < 0x80 => Ok(Enumerated(value)),
            _ => Err(reader.error(ErrorKind::Value {
                tag: Tag::Enumerated,
            })),
        }
    }
}

impl EncodeValue for Enumerated {
    fn value_len(&self) -> der::Result<Length> {
        Ok(Length::ONE)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write_byte(self.0)
    }
}

impl FixedTag for Enumerated {
    const TAG: Tag = Tag::Enumerated;
}

/// An unsigned big-endian number without leading zeros (zero is empty).
pub(crate) fn unsigned(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

/// A `GeneralizedTime` value that is not `YYYYMMDDhhmmss[.f…]Z`, or not a valid date.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid GeneralizedTime {0:?}")]
pub(crate) struct TimeError(pub String);

/// Reads a `GeneralizedTime` value: `YYYYMMDDhhmmss[.f…]Z` (RFC 3161 §2.4.2, RFC 5280
/// §4.1.2.5.2 without the fraction), fractions down to nanoseconds.
pub(crate) fn generalized_time(value: &[u8]) -> Result<OffsetDateTime, TimeError> {
    let bad = || TimeError(String::from_utf8_lossy(value).into_owned());
    let Some((&b'Z', body)) = value.split_last() else {
        return Err(bad());
    };
    let (whole, fraction) = match body.iter().position(|&b| b == b'.') {
        Some(dot) => (&body[..dot], Some(&body[dot + 1..])),
        None => (body, None),
    };
    let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    if whole.len() != 14 || !digits(whole) || fraction.is_some_and(|f| !digits(f)) {
        return Err(bad());
    }
    let number = |s: &[u8]| s.iter().fold(0u32, |n, d| n * 10 + u32::from(d - b'0'));
    let two = |at: usize| u8::try_from(number(&whole[at..at + 2])).map_err(|_| bad());
    let year = i32::try_from(number(&whole[..4])).map_err(|_| bad())?;
    let month = Month::try_from(two(4)?).map_err(|_| bad())?;
    let date = Date::from_calendar_date(year, month, two(6)?).map_err(|_| bad())?;
    // The first nine fraction digits, padded: nanoseconds.
    let nanos = (0..9).fold(0u32, |n, i| {
        let digit = fraction.and_then(|f| f.get(i)).map_or(0, |d| d - b'0');
        n * 10 + u32::from(digit)
    });
    let time = Time::from_hms_nano(two(8)?, two(10)?, two(12)?, nanos).map_err(|_| bad())?;
    Ok(PrimitiveDateTime::new(date, time).assume_utc())
}

/// `time` as a `GeneralizedTime` value `YYYYMMDDhhmmssZ`, truncated to whole seconds.
#[cfg(feature = "testing")]
pub(crate) fn format_generalized_time(time: OffsetDateTime) -> String {
    let time = time.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn generalized_time_formats() {
        assert_eq!(
            generalized_time(b"20220918132014Z"),
            Ok(datetime!(2022-09-18 13:20:14 UTC))
        );
        assert_eq!(
            generalized_time(b"20220918132014.5Z"),
            Ok(datetime!(2022-09-18 13:20:14.5 UTC))
        );
        assert_eq!(
            generalized_time(b"20220918132014.1234567891Z"),
            Ok(datetime!(2022-09-18 13:20:14.123456789 UTC))
        );
        for bad in [
            &b""[..],
            b"Z",
            b"20220918132014",
            b"2022091813201Z",
            b"20220918132014.Z",
            b"20220918132014.x5Z",
            b"2022091813201aZ",
            b"20221318132014Z",
            b"20220918250000Z",
            b"20220918132060Z",
            b"20220918132014+0600",
        ] {
            assert_eq!(
                generalized_time(bad),
                Err(TimeError(String::from_utf8_lossy(bad).into_owned()))
            );
        }
    }

    #[cfg(feature = "testing")]
    #[test]
    fn generalized_time_round_trip() {
        let t = datetime!(2026-03-01 07:08:09.75 +06:00);
        assert_eq!(format_generalized_time(t), "20260301010809Z");
        assert_eq!(
            generalized_time(format_generalized_time(t).as_bytes()),
            Ok(datetime!(2026-03-01 01:08:09 UTC))
        );
    }

    #[test]
    fn unsigned_strips_leading_zeros() {
        assert_eq!(unsigned(&[0, 0, 1, 0]), [1, 0]);
        assert_eq!(unsigned(&[0, 0]), [] as [u8; 0]);
        assert_eq!(unsigned(&[]), [] as [u8; 0]);
    }
}
