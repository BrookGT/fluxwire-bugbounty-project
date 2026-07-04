//! CBOR attestation record bundles.
//!
//! Handwritten decoder for compact binary attestation manifests used during
//! sandbox artifact verification. Records are normalized into canonical key
//! order with known wire tags stripped before policy evaluation.

mod decode;
mod value;

pub use decode::{decode_all, decode_one, MAX_CHUNK, MAX_DEPTH, MAX_ITEMS};
pub use value::{AttestationBundle, Value};

use crate::error::{Error, ErrorKind, Result};

/// Maximum records per bundle.
pub const MAX_RECORDS: usize = 10_000;

/// Tags stripped during normalization (epoch seconds, bignum, etc.).
pub const STRIP_TAGS: &[u64] = &[1, 30, 55799];

/// Parse CBOR bytes into an attestation bundle without normalization.
pub fn parse_cbor(data: &[u8]) -> Result<AttestationBundle> {
    let records = decode::decode_all(data)?;
    if records.len() > MAX_RECORDS {
        return Err(Error::with_context(
            ErrorKind::LimitExceeded,
            alloc::format!("record limit {MAX_RECORDS} exceeded"),
        ));
    }
    Ok(AttestationBundle { records })
}

/// Parse and canonicalize map keys, strip epoch tags.
pub fn parse_and_normalize(data: &[u8]) -> Result<AttestationBundle> {
    let bundle = parse_cbor(data)?;
    Ok(normalize_bundle(bundle))
}

fn normalize_bundle(bundle: AttestationBundle) -> AttestationBundle {
    let mut records = alloc::vec::Vec::with_capacity(bundle.records.len());
    for record in bundle.records {
        records.push(normalize_value(&record));
    }
    AttestationBundle { records }
}

fn normalize_value(value: &Value) -> Value {
    match value {
        Value::Tag(tag, inner) => {
            if STRIP_TAGS.contains(tag) {
                return normalize_value(inner);
            }
            Value::Tag(
                *tag,
                alloc::boxed::Box::new(normalize_value(inner)),
            )
        }
        Value::Array(items) => {
            let mut out = alloc::vec::Vec::with_capacity(items.len());
            for item in items {
                out.push(normalize_value(item));
            }
            Value::Array(out)
        }
        Value::Map(entries) => {
            let mut normalized = alloc::vec::Vec::with_capacity(entries.len());
            for (key, val) in entries {
                let nk = normalize_key(key);
                let nv = normalize_value(val);
                normalized.push((nk, nv));
            }
            sort_map_entries(&mut normalized);
            Value::Map(normalized)
        }
        Value::Text(s) => Value::Text(trim_ascii_ws(s)),
        Value::Bytes(b) => Value::Bytes(b.clone()),
        Value::Int(n) => Value::Int(*n),
        Value::Uint(n) => Value::Uint(*n),
        Value::Float(f) => Value::Float(*f),
    }
}

fn normalize_key(key: &Value) -> Value {
    match key {
        Value::Text(s) => Value::Text(trim_ascii_ws(s)),
        Value::Bytes(b) => {
            let text = alloc::string::String::from_utf8(b.clone())
                .unwrap_or_default();
            Value::Text(trim_ascii_ws(&text))
        }
        other => other.clone(),
    }
}

fn sort_map_entries(entries: &mut [(Value, Value)]) {
    entries.sort_by(|(ka, _), (kb, _)| key_ord(ka, kb));
}

fn key_ord(a: &Value, b: &Value) -> core::cmp::Ordering {
    match (a, b) {
        (Value::Text(sa), Value::Text(sb)) => sa.cmp(sb),
        (Value::Bytes(ba), Value::Bytes(bb)) => ba.cmp(bb),
        (Value::Text(_), _) => core::cmp::Ordering::Less,
        (_, Value::Text(_)) => core::cmp::Ordering::Greater,
        _ => core::cmp::Ordering::Equal,
    }
}

fn trim_ascii_ws(s: &str) -> alloc::string::String {
    let trimmed = s.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r');
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_map_record() {
        let data = alloc::vec![
            0xa2, 0x63, b'k', b'e', b'y', 0x61, b'x', 0x63, b'v', b'a', b'l', 0x18, 0x2a,
        ];
        let bundle = parse_cbor(&data).unwrap();
        assert_eq!(bundle.len(), 1);
        let map = bundle.records[0].as_map().unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_and_normalize_orders_keys() {
        let data = alloc::vec![
            0xa2, 0x61, b'z', 0x01, 0x61, b'a', 0x02,
        ];
        let bundle = parse_and_normalize(&data).unwrap();
        let map = bundle.records[0].as_map().unwrap();
        assert_eq!(map[0].0.as_text(), Some("a"));
        assert_eq!(map[1].0.as_text(), Some("z"));
    }

    #[test]
    fn strips_epoch_tag() {
        let raw = Value::Tag(1, alloc::boxed::Box::new(Value::Uint(99)));
        let norm = normalize_value(&raw);
        assert_eq!(norm, Value::Uint(99));
    }

    #[test]
    fn empty_input_yields_empty_bundle() {
        let bundle = parse_cbor(&[]).unwrap();
        assert!(bundle.is_empty());
    }

    #[test]
    fn record_limit_enforced() {
        let mut data = alloc::vec::Vec::new();
        for _ in 0..=MAX_RECORDS {
            data.push(0x00);
        }
        assert!(parse_cbor(&data).is_err());
    }
}
