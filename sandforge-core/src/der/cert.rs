//! X.509 certificate skeleton parsing from DER.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::der::oid::{
    attribute_short_name, parse_oid_tlv, signature_algorithm_name, ObjectIdentifier, OID_CN,
};
use crate::der::tlv::{
    expect_tag, parse_all_tlvs, parse_integer_bytes, parse_null, parse_octet_string, parse_tlv_at,
    Tlv, TAG_INTEGER, TAG_NULL, TAG_OID, TAG_OCTET_STRING, TAG_PRINTABLE_STRING,
    TAG_SEQUENCE, TAG_SET, TAG_UTF8_STRING,
};
use crate::error::{Error, Result};

/// Distinguished name attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub oid: ObjectIdentifier,
    pub value: String,
}

/// Relative distinguished name (one or more attributes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    pub attrs: Vec<Attribute>,
}

/// Parsed X.509 Name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub rdns: Vec<Rdn>,
}

impl Name {
    pub fn common_name(&self) -> Option<&str> {
        for rdn in &self.rdns {
            for attr in &rdn.attrs {
                if attr.oid.dotted == OID_CN {
                    return Some(attr.value.as_str());
                }
            }
        }
        None
    }

    pub fn iter_attributes(&self) -> impl Iterator<Item = &Attribute> {
        self.rdns.iter().flat_map(|r| r.attrs.iter())
    }
}

/// AlgorithmIdentifier SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    pub oid: ObjectIdentifier,
    pub parameters: Option<Vec<u8>>,
}

/// TBSCertificate fields we extract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbsCertificate {
    pub version: u32,
    pub serial: Vec<u8>,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub subject: Name,
    pub raw_len: usize,
}

/// Parsed certificate skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub tbs: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
    pub raw_len: usize,
}

impl Certificate {
    pub fn subject_cn(&self) -> Option<&str> {
        self.tbs.subject.common_name()
    }

    pub fn issuer_cn(&self) -> Option<&str> {
        self.tbs.issuer.common_name()
    }

    pub fn signature_alg_name(&self) -> &'static str {
        signature_algorithm_name(&self.signature_algorithm.oid.dotted)
    }
}

/// Generic DER value tree for `parse_der`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerValue {
    Boolean(bool),
    Integer(Vec<u8>),
    OctetString(Vec<u8>),
    Null,
    Oid(ObjectIdentifier),
    Utf8String(String),
    PrintableString(String),
    Sequence(Vec<DerValue>),
    Set(Vec<DerValue>),
    Raw { tag: u8, constructed: bool, data: Vec<u8> },
}

pub fn parse_der(data: &[u8]) -> Result<DerValue> {
    let (tlv, end) = parse_tlv_at(data, 0)?;
    if end != data.len() {
        return Err(Error::structure("trailing der data"));
    }
    tlv_to_value(&tlv)
}

fn tlv_to_value(tlv: &Tlv<'_>) -> Result<DerValue> {
    if tlv.constructed {
        let children = parse_all_tlvs(tlv.value)?;
        let values: Result<Vec<_>> = children.iter().map(tlv_to_value).collect();
        let values = values?;
        if tlv.class == 0 && tlv.tag_number == TAG_SEQUENCE as u32 {
            return Ok(DerValue::Sequence(values));
        }
        if tlv.class == 0 && tlv.tag_number == TAG_SET as u32 {
            return Ok(DerValue::Set(values));
        }
        return Ok(DerValue::Raw {
            tag: tlv.raw_tag,
            constructed: true,
            data: tlv.value.to_vec(),
        });
    }
    match tlv.universal_tag() {
        Some(TAG_INTEGER) => Ok(DerValue::Integer(parse_integer_bytes(tlv.value)?)),
        Some(TAG_OCTET_STRING) => Ok(DerValue::OctetString(parse_octet_string(tlv.value)?)),
        Some(TAG_NULL) => {
            parse_null(tlv.value)?;
            Ok(DerValue::Null)
        }
        Some(TAG_OID) => Ok(DerValue::Oid(parse_oid_tlv(tlv)?)),
        Some(TAG_UTF8_STRING) => {
            let s = parse_directory_string(tlv.value, true)?;
            Ok(DerValue::Utf8String(s))
        }
        Some(TAG_PRINTABLE_STRING) => {
            let s = parse_directory_string(tlv.value, false)?;
            Ok(DerValue::PrintableString(s))
        }
        Some(tag) => Ok(DerValue::Raw {
            tag,
            constructed: false,
            data: tlv.value.to_vec(),
        }),
        None => Ok(DerValue::Raw {
            tag: tlv.raw_tag,
            constructed: false,
            data: tlv.value.to_vec(),
        }),
    }
}

pub fn parse_certificate(data: &[u8]) -> Result<Certificate> {
    let (root, _) = parse_tlv_at(data, 0)?;
    expect_tag(&root, TAG_SEQUENCE)?;
    let children = parse_all_tlvs(root.value)?;
    if children.len() != 3 {
        return Err(Error::structure("cert field count"));
    }
    let tbs = parse_tbs_certificate(&children[0])?;
    let signature_algorithm = parse_algorithm_identifier(&children[1])?;
    let signature_value = parse_bit_string(children[2].value)?;
    Ok(Certificate {
        tbs,
        signature_algorithm,
        signature_value,
        raw_len: data.len(),
    })
}

fn parse_tbs_certificate(tlv: &Tlv<'_>) -> Result<TbsCertificate> {
    expect_tag(tlv, TAG_SEQUENCE)?;
    let items = parse_all_tlvs(tlv.value)?;
    if items.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let mut idx = 0usize;
    let version = if items[0].class == 0xa0 {
        let ver_tlv = parse_context_explicit_integer(items[0].value)?;
        idx += 1;
        ver_tlv + 1
    } else {
        0
    };
    if idx + 3 > items.len() {
        return Err(Error::structure("tbs short"));
    }
    let serial = parse_integer_bytes(items[idx].value)?;
    idx += 1;
    let signature = parse_algorithm_identifier(&items[idx])?;
    idx += 1;
    let issuer = parse_name(&items[idx])?;
    idx += 1;
    if idx >= items.len() {
        return Err(Error::structure("tbs missing validity"));
    }
    idx += 1;
    if idx >= items.len() {
        return Err(Error::structure("tbs missing subject"));
    }
    let subject = parse_name(&items[idx])?;
    Ok(TbsCertificate {
        version,
        serial,
        signature,
        issuer,
        subject,
        raw_len: tlv.value.len(),
    })
}

fn parse_context_explicit_integer(data: &[u8]) -> Result<u32> {
    let tlvs = parse_all_tlvs(data)?;
    if tlvs.len() != 1 {
        return Err(Error::structure("version wrap"));
    }
    expect_tag(&tlvs[0], TAG_INTEGER)?;
    let bytes = parse_integer_bytes(tlvs[0].value)?;
    if bytes.len() > 4 {
        return Err(Error::structure("version int"));
    }
    let mut v = 0u32;
    for b in bytes {
        v = (v << 8) | b as u32;
    }
    Ok(v)
}

fn parse_algorithm_identifier(tlv: &Tlv<'_>) -> Result<AlgorithmIdentifier> {
    expect_tag(tlv, TAG_SEQUENCE)?;
    let items = parse_all_tlvs(tlv.value)?;
    if items.is_empty() {
        return Err(Error::structure("alg id empty"));
    }
    let oid = parse_oid_tlv(&items[0])?;
    let parameters = if items.len() > 1 {
        Some(items[1].value.to_vec())
    } else {
        None
    };
    Ok(AlgorithmIdentifier { oid, parameters })
}

fn parse_name(tlv: &Tlv<'_>) -> Result<Name> {
    expect_tag(tlv, TAG_SEQUENCE)?;
    let set_tlvs = parse_all_tlvs(tlv.value)?;
    let mut rdns = Vec::with_capacity(set_tlvs.len());
    for set_tlv in set_tlvs {
        expect_tag(&set_tlv, TAG_SET)?;
        let attr_tlvs = parse_all_tlvs(set_tlv.value)?;
        let mut attrs = Vec::with_capacity(attr_tlvs.len());
        for at in attr_tlvs {
            attrs.push(parse_attribute(&at)?);
        }
        rdns.push(Rdn { attrs });
    }
    Ok(Name { rdns })
}

fn parse_attribute(tlv: &Tlv<'_>) -> Result<Attribute> {
    expect_tag(tlv, TAG_SEQUENCE)?;
    let items = parse_all_tlvs(tlv.value)?;
    if items.len() < 2 {
        return Err(Error::structure("attr short"));
    }
    let oid = parse_oid_tlv(&items[0])?;
    let value = parse_attribute_value(&items[1])?;
    Ok(Attribute { oid, value })
}

fn parse_attribute_value(tlv: &Tlv<'_>) -> Result<String> {
    match tlv.universal_tag() {
        Some(TAG_UTF8_STRING) => parse_directory_string(tlv.value, true),
        Some(TAG_PRINTABLE_STRING) => parse_directory_string(tlv.value, false),
        Some(TAG_OCTET_STRING) => {
            let bytes = parse_octet_string(tlv.value)?;
            Ok(hex_encode(&bytes))
        }
        _ => Err(Error::structure("attr value type")),
    }
}

fn parse_directory_string(data: &[u8], utf8: bool) -> Result<String> {
    for &b in data {
        if b > 0x7f {
            return Err(Error::structure("non-ascii string"));
        }
    }
    let s = if utf8 {
        core::str::from_utf8(data).map_err(|_| Error::structure("utf8"))?
    } else {
        core::str::from_utf8(data).map_err(|_| Error::structure("printable"))?
    };
    Ok(String::from(s))
}

fn parse_bit_string(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::structure("empty bit string"));
    }
    let unused = data[0];
    if unused > 7 {
        return Err(Error::structure("bit string unused"));
    }
    Ok(data[1..].to_vec())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn format_name(name: &Name) -> String {
    let mut parts = Vec::new();
    for attr in name.iter_attributes() {
        let label = attribute_short_name(&attr.oid.dotted).unwrap_or("OID");
        let mut piece = String::new();
        piece.push_str(label);
        piece.push('=');
        piece.push_str(&attr.value);
        parts.push(piece);
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_null_der() {
        let der = [0x05, 0x00];
        let v = parse_der(&der).unwrap();
        assert_eq!(v, DerValue::Null);
    }

    #[test]
    fn parse_int_der() {
        let der = [0x02, 0x01, 0x2a];
        let v = parse_der(&der).unwrap();
        assert_eq!(v, DerValue::Integer(vec![0x2a]));
    }
}
