//! Exact monetary values. JSON amounts are decimal strings of integer zatoshis.
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use thiserror::Error;

pub const ZATOSHIS_PER_ZEC: u64 = 100_000_000;
/// Zcash's maximum monetary supply; individual amounts and aggregate accounting
/// are bounded independently, even though the underlying integer is larger.
pub const MAX_MONEY: u64 = 21_000_000 * ZATOSHIS_PER_ZEC;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AmountError {
    #[error("amount must be an unsigned canonical decimal string")]
    InvalidDecimal,
    #[error("ZEC amounts allow at most eight fractional decimal places")]
    ExcessPrecision,
    #[error("amount exceeds the maximum monetary range")]
    OutOfRange,
    #[error("monetary subtraction would be negative")]
    Underflow,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);

    pub fn from_zatoshis(value: u64) -> Result<Self, AmountError> {
        if value > MAX_MONEY {
            return Err(AmountError::OutOfRange);
        }
        Ok(Self(value))
    }

    pub const fn as_zatoshis(self) -> u64 {
        self.0
    }

    pub fn parse_zatoshis(input: &str) -> Result<Self, AmountError> {
        if !canonical_digits(input) {
            return Err(AmountError::InvalidDecimal);
        }
        Self::from_zatoshis(input.parse().map_err(|_| AmountError::OutOfRange)?)
    }

    /// Parse human-entered ZEC without floats, exponent syntax, trimming,
    /// locale-specific punctuation, signs, or precision rounding.
    pub fn parse_zec(input: &str) -> Result<Self, AmountError> {
        let (whole, fractional) = match input.split_once('.') {
            Some((whole, fractional)) => {
                if fractional.is_empty() || !fractional.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(AmountError::InvalidDecimal);
                }
                if fractional.len() > 8 {
                    return Err(AmountError::ExcessPrecision);
                }
                (whole, fractional)
            }
            None => (input, ""),
        };
        if !canonical_digits(whole) {
            return Err(AmountError::InvalidDecimal);
        }
        let whole: u64 = whole.parse().map_err(|_| AmountError::OutOfRange)?;
        let fractional = if fractional.is_empty() {
            0
        } else {
            let value: u64 = fractional
                .parse()
                .map_err(|_| AmountError::InvalidDecimal)?;
            value * 10u64.pow(8 - fractional.len() as u32)
        };
        let value = whole
            .checked_mul(ZATOSHIS_PER_ZEC)
            .and_then(|value| value.checked_add(fractional))
            .ok_or(AmountError::OutOfRange)?;
        Self::from_zatoshis(value)
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        Self::from_zatoshis(self.0.checked_add(other.0).ok_or(AmountError::OutOfRange)?)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        Ok(Self(
            self.0.checked_sub(other.0).ok_or(AmountError::Underflow)?,
        ))
    }

    pub fn checked_sum(values: impl IntoIterator<Item = Self>) -> Result<Self, AmountError> {
        values.into_iter().try_fold(Self::ZERO, Self::checked_add)
    }

    pub fn to_zec(self) -> String {
        format!(
            "{}.{:08}",
            self.0 / ZATOSHIS_PER_ZEC,
            self.0 % ZATOSHIS_PER_ZEC
        )
    }
}

fn canonical_digits(input: &str) -> bool {
    !input.is_empty()
        && input.bytes().all(|b| b.is_ascii_digit())
        && (input == "0" || !input.starts_with('0'))
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} zatoshis)", self.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Amount {
    type Err = AmountError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_zatoshis(input)
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse_zatoshis(&value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zec_parsing_is_exact_and_strict() {
        assert_eq!(Amount::parse_zec("0.00000001").unwrap().as_zatoshis(), 1);
        assert_eq!(
            Amount::parse_zec("2.00006").unwrap().as_zatoshis(),
            200_006_000
        );
        for invalid in [
            "",
            " 1",
            "1 ",
            "+1",
            "-1",
            "1e2",
            "01",
            ".5",
            "1.",
            "1,5",
            "１",
            "0.000000001",
            "21000000.00000001",
        ] {
            assert!(Amount::parse_zec(invalid).is_err(), "accepted {invalid:?}");
        }
        assert_eq!(
            Amount::parse_zec("21000000").unwrap().as_zatoshis(),
            MAX_MONEY
        );
    }

    #[test]
    fn json_requires_integer_decimal_strings() {
        assert_eq!(
            serde_json::to_string(&Amount::from_zatoshis(42).unwrap()).unwrap(),
            "\"42\""
        );
        for invalid in [
            "42",
            "42.0",
            "\"042\"",
            "\"4.2\"",
            "\"-1\"",
            "null",
            "\"184467440737095516160\"",
        ] {
            assert!(serde_json::from_str::<Amount>(invalid).is_err());
        }
    }

    #[test]
    fn checked_arithmetic_never_wraps_or_exceeds_supply() {
        let max = Amount::from_zatoshis(MAX_MONEY).unwrap();
        let one = Amount::from_zatoshis(1).unwrap();
        assert_eq!(max.checked_add(one), Err(AmountError::OutOfRange));
        assert_eq!(Amount::ZERO.checked_sub(one), Err(AmountError::Underflow));
        assert_eq!(
            Amount::from_zatoshis(u64::MAX),
            Err(AmountError::OutOfRange)
        );
        assert_eq!(
            Amount::checked_sum([max, one]),
            Err(AmountError::OutOfRange)
        );
    }
}
