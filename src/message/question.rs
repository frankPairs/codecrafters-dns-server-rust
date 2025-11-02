use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;

use crate::message::{constants::DNS_MESSAGE_PACKET_SIZE, error::DnsMessageError, types::DnsClass};

use super::types::DnsType;

#[derive(Debug, Clone)]
pub struct DomainLabel {
    pub name: String,
    pub pointer: usize,
}

impl std::borrow::Borrow<str> for DomainLabel {
    fn borrow(&self) -> &str {
        self.name.as_str()
    }
}

#[derive(Debug, Default)]
pub struct DomainName {
    labels: Vec<DomainLabel>,
}

impl DomainName {
    pub fn add_label(&mut self, new_label: DomainLabel) {
        self.labels.push(new_label);
    }

    pub fn as_slice(&self, start_pointer: &DomainLabelPointer) -> &[DomainLabel] {
        &self.labels[start_pointer.index_position..]
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.labels.join(".");

        write!(f, "{}", name)
    }
}

#[derive(Debug)]
pub struct DomainLabelPointer {
    pub domain_name: String,
    pub index_position: usize,
}

#[derive(Debug, Default)]
pub struct DomainNames {
    names: HashMap<String, DomainName>,
    label_pointers: HashMap<usize, DomainLabelPointer>,
}

impl DomainNames {
    pub fn add_name(&mut self, domain_name: DomainName) {
        let name = domain_name.to_string();

        for (index, label) in domain_name.labels.iter().enumerate() {
            let label_pointer = DomainLabelPointer {
                domain_name: name.clone(),
                index_position: index,
            };

            self.label_pointers.insert(label.pointer, label_pointer);
        }

        self.names.insert(name, domain_name);
    }

    pub fn get_labels_by_pointer(&self, pointer: usize) -> Option<&[DomainLabel]> {
        let label_pointer = self.label_pointers.get(&pointer)?;
        let domain_name = self.names.get(&label_pointer.domain_name)?;

        Some(domain_name.as_slice(label_pointer))
    }
}
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

#[derive(Debug)]
pub struct DnsQuestionsEncoder;

impl DnsQuestionsEncoder {
    pub fn encode(&self, questions: &Vec<DnsQuestion>) -> Bytes {
        let mut buf = BytesMut::new();

        for question in questions {
            buf.put(self.encode_question(question));
        }

        Bytes::from(buf)
    }

    fn encode_question(&self, question: &DnsQuestion) -> Bytes {
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

/// Questions decoder supports message compression.
/// For more information about how compression works, you can check the official documentation in
/// the following link:
///
/// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
pub struct DnsQuestionsDecoder<'a> {
    buf: &'a mut Bytes,
    question_count: u16,
    domain_names: DomainNames,
}

impl<'a> DnsQuestionsDecoder<'a> {
    pub fn new(buf: &'a mut Bytes, question_count: u16) -> Self {
        Self {
            buf,
            question_count,
            domain_names: DomainNames::default(),
        }
    }

    pub fn decode(mut self) -> Result<Vec<DnsQuestion>, DnsMessageError> {
        let mut questions: Vec<DnsQuestion> = Vec::with_capacity(self.question_count as usize);

        for _ in 0..self.question_count {
            let question = self.decode_question()?;

            questions.push(question);
        }

        Ok(questions)
    }

    fn decode_question(&mut self) -> Result<DnsQuestion, DnsMessageError> {
        let mut domain_name = DomainName::default();

        loop {
            let label_length = self.buf.get_u8();

            if label_length == 0 {
                break;
            }

            if self.is_pointer(label_length) {
                let pointer = self.buf.get_u8();

                match self.domain_names.get_labels_by_pointer(pointer as usize) {
                    Some(labels) => {
                        for label in labels {
                            domain_name.add_label(label.clone());
                        }

                        break;
                    }
                    None => {
                        break;
                    }
                };
            }

            let pointer_position = self.get_cursor_position();
            let bytes = self.buf.copy_to_bytes(label_length as usize);
            let label = std::str::from_utf8(&bytes[..])
                .map_err(|err| DnsMessageError::DecodeQuestion(err.to_string()))?;
            let domain_label = DomainLabel {
                pointer: pointer_position,
                name: label.to_string(),
            };

            domain_name.add_label(domain_label);
        }

        let name = domain_name.to_string();
        let kind = DnsQuestionType::try_from(self.buf.get_u16())?;
        let class = DnsQuestionClass::try_from(self.buf.get_u16())?;

        self.domain_names.add_name(domain_name);

        Ok(DnsQuestion { name, kind, class })
    }

    // When the first two bits are ones, we know that it is a pointer.
    // This allows a pointer to be distinguished from a label, since the
    // label must begin with two zero bits because labels are restricted to 63 octets or less.
    fn is_pointer(&self, byte: u8) -> bool {
        byte & 0b1100_000 > 0
    }

    // Gets the buffer cursor positions, which it's used when compressing domain names. The
    // cursor position is used as a pointer to a specific domain label.
    fn get_cursor_position(&self) -> usize {
        (DNS_MESSAGE_PACKET_SIZE - self.buf.remaining()) - 1
    }
}
