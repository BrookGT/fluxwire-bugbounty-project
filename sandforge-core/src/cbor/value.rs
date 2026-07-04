//! CBOR value tree for attestation record bundles.

use alloc::string::String;
use alloc::vec::Vec;

/// A decoded CBOR item from an attestation record.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Signed integer (major type 0/1 combined).
    Int(i64),
    /// Unsigned integer when the wire form was major type 0 only.
    Uint(u64),
    /// IEEE-754 float (half, single, or double).
    Float(f64),
    /// Raw byte string (signature, digest, cert DER).
    Bytes(Vec<u8>),
    /// UTF-8 text string (issuer, subject, policy id).
    Text(String),
    /// Ordered sequence of values.
    Array(Vec<Value>),
    /// Key/value map (claims, extensions).
    Map(Vec<(Value, Value)>),
    /// Tagged value (epoch seconds, COSE, etc.).
    Tag(u64, Box<Value>),
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            Value::Uint(v) if *v <= i64::MAX as u64 => Some(*v as i64),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => Some(*v),
            Value::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(v) => Some(*v),
            Value::Int(v) => Some(*v as f64),
            Value::Uint(v) => Some(*v as f64),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    pub fn map_get(&self, key: &str) -> Option<&Value> {
        let map = self.as_map()?;
        for (k, v) in map {
            if k.as_text() == Some(key) {
                return Some(v);
            }
        }
        None
    }

    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.map_get(name)
    }
}

/// Parsed attestation record bundle (one or more top-level CBOR items).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttestationBundle {
    pub records: Vec<Value>,
}

impl AttestationBundle {
    pub fn new() -> Self {
        AttestationBundle {
            records: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn push(&mut self, value: Value) {
        self.records.push(value);
    }

    /// Return the first record that looks like a claim map.
    pub fn primary_claims(&self) -> Option<&Value> {
        self.records.iter().find(|r| r.as_map().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_get_finds_claim() {
        let v = Value::Map(alloc::vec![(
            Value::Text(String::from("issuer")),
            Value::Text(String::from("sandforge-ca")),
        )]);
        assert_eq!(
            v.claim("issuer").and_then(Value::as_text),
            Some("sandforge-ca")
        );
    }

    #[test]
    fn numeric_coercions() {
        let u = Value::Uint(42);
        assert_eq!(u.as_int(), Some(42));
        assert_eq!(u.as_float(), Some(42.0));
    }

    #[test]
    fn primary_claims_selects_map() {
        let mut bundle = AttestationBundle::new();
        bundle.push(Value::Uint(1));
        bundle.push(Value::Map(alloc::vec![]));
        assert!(bundle.primary_claims().unwrap().as_map().is_some());
    }
}
