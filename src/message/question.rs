use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::message::{error::DnsMessageError, types::DnsClass};

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

impl TryFrom<u16> for DnsQuestionType {
    type Error = DnsMessageError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            252 => Ok(DnsQuestionType::AXFR),
            253 => Ok(DnsQuestionType::MAILB),
            254 => Ok(DnsQuestionType::MAILA),
            255 => Ok(DnsQuestionType::ALL),
            num => {
                let dns_type = DnsType::try_from(num)?;

                Ok(DnsQuestionType::DnsType(dns_type))
            }
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

impl TryFrom<u16> for DnsQuestionClass {
    type Error = DnsMessageError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            255 => Ok(DnsQuestionClass::ALL),
            num => {
                let dns_class = DnsClass::try_from(num)?;

                Ok(DnsQuestionClass::DnsClass(dns_class))
            }
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

pub struct DnsQuestionDecoder;

impl DnsQuestionDecoder {
    pub fn decode(buf: &mut Bytes) -> Result<DnsQuestion, DnsMessageError> {
        let read_label_completed = false;
        let mut name_label_list: Vec<String> = Vec::new();

        while read_label_completed == false {
            let label_length = buf.get_u8();

            if label_length == 0 {
                break;
            }

            let bytes = buf.copy_to_bytes(label_length as usize);

            let label = std::str::from_utf8(&bytes[..])
                .map_err(|err| DnsMessageError::DecodeQuestion(err.to_string()))?;

            name_label_list.push(label.to_string());
        }

        let name = name_label_list.join(".");

        let kind = DnsQuestionType::try_from(buf.get_u16())?;
        let class = DnsQuestionClass::try_from(buf.get_u16())?;

        Ok(DnsQuestion { name, kind, class })
    }
}
