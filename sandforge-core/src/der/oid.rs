//! ASN.1 OBJECT IDENTIFIER decoding and known OID registry.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::der::tlv::{expect_tag, TAG_OID};
use crate::der::tlv::Tlv;
use crate::error::{Error, Result};

/// Decoded object identifier arc sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier {
    pub arcs: Vec<u32>,
    pub dotted: String,
}

impl ObjectIdentifier {
    pub fn from_arcs(arcs: Vec<u32>) -> Result<Self> {
        if arcs.len() < 2 {
            return Err(Error::structure("oid too short"));
        }
        if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
            return Err(Error::structure("oid first arcs"));
        }
        let dotted = arcs_to_dotted(&arcs);
        Ok(ObjectIdentifier { arcs, dotted })
    }

    pub fn is_rsa_encryption(&self) -> bool {
        self.dotted == OID_RSA_ENCRYPTION
    }

    pub fn is_sha256_with_rsa(&self) -> bool {
        self.dotted == OID_SHA256_WITH_RSA
    }

    pub fn is_ec_public_key(&self) -> bool {
        self.dotted == OID_EC_PUBLIC_KEY
    }
}

pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_CN: &str = "2.5.4.3";
pub const OID_O: &str = "2.5.4.10";
pub const OID_OU: &str = "2.5.4.11";
pub const OID_C: &str = "2.5.4.6";

/// Parse DER OBJECT IDENTIFIER contents (not including tag/length).
pub fn parse_oid_bytes(data: &[u8]) -> Result<ObjectIdentifier> {
    if data.is_empty() {
        return Err(Error::structure("empty oid"));
    }
    let mut arcs = Vec::new();
    let first = data[0];
    arcs.push((first / 40) as u32);
    arcs.push((first % 40) as u32);
    let mut idx = 1usize;
    while idx < data.len() {
        let (val, consumed) = parse_base128(&data[idx..])?;
        arcs.push(val);
        idx += consumed;
    }
    ObjectIdentifier::from_arcs(arcs)
}

pub fn parse_oid_tlv(tlv: &Tlv<'_>) -> Result<ObjectIdentifier> {
    expect_tag(tlv, TAG_OID)?;
    parse_oid_bytes(tlv.value)
}

fn parse_base128(data: &[u8]) -> Result<(u32, usize)> {
    let mut val = 0u32;
    for (i, &b) in data.iter().enumerate() {
        val = val
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7f) as u32))
            .ok_or(Error::structure("oid overflow"))?;
        if b & 0x80 == 0 {
            return Ok((val, i + 1));
        }
        if i > 4 {
            return Err(Error::structure("oid arc too long"));
        }
    }
    Err(Error::structure("oid truncated"))
}

fn arcs_to_dotted(arcs: &[u32]) -> String {
    let mut s = String::new();
    for (i, arc) in arcs.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        push_u32(&mut s, *arc);
    }
    s
}

fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut n = 0usize;
    while v > 0 {
        buf[n] = (v % 10) as u8 + b'0';
        n += 1;
        v /= 10;
    }
    while n > 0 {
        n -= 1;
        s.push(buf[n] as char);
    }
}

/// Map common attribute OIDs to short names.
pub fn attribute_short_name(oid: &str) -> Option<&'static str> {
    match oid {
        OID_CN => Some("CN"),
        OID_O => Some("O"),
        OID_OU => Some("OU"),
        OID_C => Some("C"),
        _ => None,
    }
}

/// Map signature algorithm OIDs to ASCII labels.
pub fn signature_algorithm_name(oid: &str) -> &'static str {
    match oid {
        OID_RSA_ENCRYPTION => "rsaEncryption",
        OID_SHA256_WITH_RSA => "sha256WithRSAEncryption",
        OID_EC_PUBLIC_KEY => "id-ecPublicKey",
        _ => "unknown",
    }
}

pub fn encode_oid_first_two(a0: u32, a1: u32) -> Result<u8> {
    if a0 > 2 {
        return Err(Error::structure("oid arc0"));
    }
    if a0 < 2 && a1 > 39 {
        return Err(Error::structure("oid arc1"));
    }
    Ok((a0 * 40 + a1) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rsa_oid() {
        let der: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        let (tlv, _) = crate::der::tlv::parse_tlv_at(der, 0).unwrap();
        let oid = parse_oid_tlv(&tlv).unwrap();
        assert!(oid.is_rsa_encryption());
        assert_eq!(oid.dotted, OID_RSA_ENCRYPTION);
    }

    #[test]
    fn dotted_form() {
        let oid = ObjectIdentifier::from_arcs(vec![1, 2, 840, 113549, 1, 1, 1]).unwrap();
        assert_eq!(oid.dotted, OID_RSA_ENCRYPTION);
    }
}
