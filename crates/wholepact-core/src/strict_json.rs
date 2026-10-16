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
}
