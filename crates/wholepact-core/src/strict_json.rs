//! Bounded JSON import with duplicate keys rejected before building a Value.
use crate::{CoreError, ErrorCode, Result};
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub const MAX_JSON_BYTES: usize = 1_048_576;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_NODES: usize = 16_384;

#[derive(Default)]
struct Budget {
    nodes: usize,
    exhausted: bool,
}

struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        self.budget.nodes += 1;
        if self.depth > MAX_JSON_DEPTH || self.budget.nodes > MAX_JSON_NODES {
            self.budget.exhausted = true;
            return Err(de::Error::custom("JSON resource limit exceeded"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub fn parse_json_unique(input: &[u8]) -> Result<Value> {
    if input.len() > MAX_JSON_BYTES {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "JSON body exceeds 1 MiB",
        ));
    }
    parse_json_unique_inner(input)
}

// Explicit aggregate envelopes may contain several independently bounded
// artifacts. This is never the default parser limit or a caller-provided wire
// setting. Depth and node budgets remain identical for every entry point.
const MAX_CALLER_CAPPED_JSON_BYTES: usize = 5 * MAX_JSON_BYTES;

fn parse_json_unique_with_byte_limit(input: &[u8], maximum_bytes: usize) -> Result<Value> {
    if maximum_bytes == 0
        || maximum_bytes > MAX_CALLER_CAPPED_JSON_BYTES
        || input.len() > maximum_bytes
    {
        return Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "JSON body exceeds the explicit bounded import limit",
        ));
    }
    parse_json_unique_inner(input)
}

fn parse_json_unique_inner(input: &[u8]) -> Result<Value> {
    let mut budget = Budget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let parsed = Seed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer);
    match parsed {
        Ok(value) => {
            deserializer.end().map_err(|_| {
                CoreError::new(
                    ErrorCode::InvalidTerms,
                    "unexpected content after the JSON value",
                )
            })?;
            Ok(value)
        }
        Err(_) if budget.exhausted => Err(CoreError::new(
            ErrorCode::ResourceLimit,
            "JSON exceeds the depth or node-count limit",
        )),
        Err(_) => Err(CoreError::new(
            ErrorCode::InvalidTerms,
            "invalid JSON or duplicate object key",
        )),
    }
}

pub fn parse_typed_json<T: DeserializeOwned>(input: &[u8]) -> Result<T> {
    serde_json::from_value(parse_json_unique(input)?).map_err(|_| {
        CoreError::new(
            ErrorCode::InvalidTerms,
            "JSON fields, types, or monetary encodings do not match the required schema",
        )
    })
}

/// Explicit bounded aggregate import. The trusted caller must supply its
/// protocol constant, not a value from the request. The hard ceiling is 5 MiB;
/// duplicate-key, depth (32), node-count (16,384), typed-schema and trailing-data
/// checks are unchanged. Ordinary `parse_typed_json` remains limited to 1 MiB.
pub fn parse_typed_json_with_byte_limit<T: DeserializeOwned>(
    input: &[u8],
    maximum_bytes: usize,
) -> Result<T> {
    serde_json::from_value(parse_json_unique_with_byte_limit(input, maximum_bytes)?).map_err(|_| {
        CoreError::new(
            ErrorCode::InvalidTerms,
            "JSON fields, types, or monetary encodings do not match the required schema",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_duplicate_keys_and_trailing_values_fail() {
        for source in [
            r#"{"amount":"1","amount":"2"}"#,
            r#"{"extensions":[{"value":{"x":1,"x":2}}]}"#,
            r#"{} {}"#,
        ] {
            assert!(parse_json_unique(source.as_bytes()).is_err());
        }
        assert!(parse_json_unique(br#"{"a":[null,true,1,"ok"],"b":{}}"#).is_ok());
    }
    #[test]
    fn depth_nodes_and_size_are_bounded() {
        let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert_eq!(
            parse_json_unique(deep.as_bytes()).unwrap_err().code,
            ErrorCode::ResourceLimit
        );
        let wide = format!("[{}0]", "0,".repeat(MAX_JSON_NODES));
        assert_eq!(
            parse_json_unique(wide.as_bytes()).unwrap_err().code,
            ErrorCode::ResourceLimit
        );
        assert_eq!(
            parse_json_unique(&vec![b' '; MAX_JSON_BYTES + 1])
                .unwrap_err()
                .code,
            ErrorCode::ResourceLimit
        );
    }
    #[test]
    fn explicit_aggregate_limit_does_not_change_default_or_hard_ceiling() {
        let source = format!("\"{}\"", "a".repeat(MAX_JSON_BYTES));
        assert_eq!(
            parse_typed_json::<String>(source.as_bytes())
                .unwrap_err()
                .code,
            ErrorCode::ResourceLimit
        );
        assert_eq!(
            parse_typed_json_with_byte_limit::<String>(source.as_bytes(), source.len())
                .unwrap()
                .len(),
            MAX_JSON_BYTES
        );
        assert!(
            parse_typed_json_with_byte_limit::<String>(source.as_bytes(), source.len() - 1)
                .is_err()
        );
        for limit in [0, MAX_CALLER_CAPPED_JSON_BYTES + 1, usize::MAX] {
            assert_eq!(
                parse_typed_json_with_byte_limit::<Value>(b"{}", limit)
                    .unwrap_err()
                    .code,
                ErrorCode::ResourceLimit
            );
        }
        let boundary = format!("\"{}\"", "b".repeat(MAX_CALLER_CAPPED_JSON_BYTES - 2));
        assert!(
            parse_typed_json_with_byte_limit::<String>(
                boundary.as_bytes(),
                MAX_CALLER_CAPPED_JSON_BYTES
            )
            .is_ok()
        );
        let too_large = format!("{} ", boundary);
        assert_eq!(
            parse_typed_json_with_byte_limit::<String>(
                too_large.as_bytes(),
                MAX_CALLER_CAPPED_JSON_BYTES
            )
            .unwrap_err()
            .code,
            ErrorCode::ResourceLimit
        );
    }
    #[test]
    fn explicit_aggregate_preserves_strict_depth_nodes_and_duplicate_checks() {
        for source in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"\u0061":2}"#,
            r#"{"nested":{"x":1,"x":2}}"#,
            "{} {}",
        ] {
            assert!(
                parse_typed_json_with_byte_limit::<Value>(
                    source.as_bytes(),
                    MAX_CALLER_CAPPED_JSON_BYTES
                )
                .is_err()
            );
        }
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        let wide = format!("[{}0]", "0,".repeat(MAX_JSON_NODES));
        for source in [deep, wide] {
            assert_eq!(
                parse_typed_json_with_byte_limit::<Value>(
                    source.as_bytes(),
                    MAX_CALLER_CAPPED_JSON_BYTES
                )
                .unwrap_err()
                .code,
                ErrorCode::ResourceLimit
            );
        }
        let allowed_depth = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        );
        assert!(
            parse_typed_json_with_byte_limit::<Value>(
                allowed_depth.as_bytes(),
                MAX_CALLER_CAPPED_JSON_BYTES
            )
            .is_ok()
        );
        let allowed_nodes = format!("[{}0]", "0,".repeat(MAX_JSON_NODES - 2));
        assert!(
            parse_typed_json_with_byte_limit::<Value>(
                allowed_nodes.as_bytes(),
                MAX_CALLER_CAPPED_JSON_BYTES
            )
            .is_ok()
        );
    }
}
