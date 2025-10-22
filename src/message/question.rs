use bytes::{BufMut, Bytes, BytesMut};

use crate::message::types::DnsClass;

use super::types::DnsType;

/// The question section contains a list of questions (usually just 1) that the sender wants to ask the receiver. This section is present in both query and reply packets.
#[derive(Debug)]
pub struct DnsQuestion {
    /// A domain name, represented as a sequence of "labels" (more on this below)
    pub name: String,
    pub kind: DnsQuestionType,
    pub class: DnsQuestionClass,
}

/// QTYPE fields appear in the question part of a query.  QTYPES are a
/// superset of TYPEs, hence all TYPEs are valid QTYPEs.
#[derive(Debug, Clone, Copy)]
pub enum DnsQuestionType {
    DnsType(DnsType),
    AXFR,
    /// 253 A request for mailbox-related records (MB, MG or MR)
    MAILB,
    /// 254 A request for mail agent RRs (Obsolete - see MX)
    MAILA,
    /// 255 A request for all records
    ALL,
}

impl Into<u16> for DnsQuestionType {
    fn into(self) -> u16 {
        match self {
            DnsQuestionType::DnsType(dns_type) => dns_type.into(),
            DnsQuestionType::AXFR => 252,
            DnsQuestionType::MAILB => 253,
            DnsQuestionType::MAILA => 254,
            DnsQuestionType::ALL => 255,
        }
    }
}

/// QCLASS fields appear in the question section of a query.  QCLASS values
/// are a superset of CLASS values; every CLASS is a valid QCLASS.  In
/// addition to CLASS values, the following QCLASSes are defined:
#[derive(Debug, Clone, Copy)]
pub enum DnsQuestionClass {
    DnsClass(DnsClass),
    ALL,
}

impl Into<u16> for DnsQuestionClass {
    fn into(self) -> u16 {
        match self {
            DnsQuestionClass::DnsClass(dns_class) => dns_class.into(),
            DnsQuestionClass::ALL => 255,
        }
    }
}

pub struct DnsQuestionEncoder;

impl DnsQuestionEncoder {
    pub fn encode(question: &DnsQuestion) -> Bytes {
        let mut buf = BytesMut::new();
        let mut encoded_name = BytesMut::new();
        let question_parts = question.name.split(".");

        for part in question_parts {
            let label_length: u8 = part.len() as u8;

            encoded_name.put_u8(label_length);
            encoded_name.put(part.as_bytes());
        }

        encoded_name.put_u8(0);

        buf.put(encoded_name);

        buf.put_u16(question.kind.into());

        buf.put_u16(question.class.into());

        Bytes::from(buf)
    }
}
