//! ASN.1 DER parsing for X.509 certificates and generic TLV trees.

mod cert;
mod oid;
mod tlv;

pub use cert::{
    format_name, parse_certificate, parse_der, AlgorithmIdentifier, Attribute, Certificate,
    DerValue, Name, Rdn, TbsCertificate,
};
pub use oid::{
    attribute_short_name, parse_oid_bytes, parse_oid_tlv, signature_algorithm_name, ObjectIdentifier,
    OID_CN, OID_RSA_ENCRYPTION, OID_SHA256_WITH_RSA,
};
pub use tlv::{
    decode_length, decode_tag, parse_all_tlvs, parse_integer_bytes, parse_integer_u64,
    parse_octet_string, parse_tlv_at, read_octet_string_bulk, tag_name, Tlv, TAG_INTEGER,
    TAG_OCTET_STRING, TAG_SEQUENCE,
};

use crate::error::Result;

/// Parse DER and validate that the outer structure is a SEQUENCE (typical for certs).
pub fn parse_and_validate_sequence(data: &[u8]) -> Result<DerValue> {
    let value = parse_der(data)?;
    match &value {
        DerValue::Sequence(_) => Ok(value),
        _ => Err(crate::error::Error::structure("expected sequence")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexport_tlv() {
        let der = [0x30, 0x00];
        let v = parse_der(&der).unwrap();
        assert!(matches!(v, DerValue::Sequence(_)));
    }
}
