use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;

use crate::message::{constants::DNS_MESSAGE_PACKET_SIZE, error::ServerError, types::DnsClass};

use super::types::{DnsType, DomainLabel, DomainName};

#[derive(Debug)]
pub struct QuestionDomainLabelPointer {
    pub domain_name: String,
    pub index_position: usize,
}

#[derive(Debug, Default)]
pub struct QuestionDomainNames {
    names: HashMap<String, DomainName>,
    label_pointers: HashMap<usize, QuestionDomainLabelPointer>,
}

impl QuestionDomainNames {
    pub fn add_name(&mut self, domain_name: DomainName) {
        let name = domain_name.to_string();
        let labels = domain_name.get_labels();

        for (index, label) in labels.iter().enumerate() {
            let label_pointer = QuestionDomainLabelPointer {
                domain_name: name.clone(),
                index_position: index,
            };

            if let Some(pointer) = label.pointer {
                self.label_pointers.insert(pointer, label_pointer);
            }
        }

        self.names.insert(name, domain_name);
    }

    pub fn get_labels_by_pointer(&self, pointer: usize) -> Option<&[DomainLabel]> {
        let label_pointer = self.label_pointers.get(&pointer)?;
        let domain_name = self.names.get(&label_pointer.domain_name)?;

        Some(domain_name.as_slice(label_pointer.index_position))
    }
}

/// The question section contains a list of questions (usually just 1) that the sender wants to ask the receiver. This section is present in both query and reply packets.
#[derive(Debug, Clone)]
pub struct Question {
    /// A domain name, represented as a sequence of "labels" (more on this below)
    pub name: String,
    pub kind: QuestionType,
    pub class: QuestionClass,
}

/// QTYPE fields appear in the question part of a query.  QTYPES are a
/// superset of TYPEs, hence all TYPEs are valid QTYPEs.
#[derive(Debug, Clone, Copy)]
pub enum QuestionType {
    DnsType(DnsType),
    AXFR,
    /// 253 A request for mailbox-related records (MB, MG or MR)
    MAILB,
    /// 254 A request for mail agent RRs (Obsolete - see MX)
    MAILA,
    /// 255 A request for all records
    ALL,
}

impl Into<u16> for QuestionType {
    fn into(self) -> u16 {
        match self {
            QuestionType::DnsType(dns_type) => dns_type.into(),
            QuestionType::AXFR => 252,
            QuestionType::MAILB => 253,
            QuestionType::MAILA => 254,
            QuestionType::ALL => 255,
        }
    }
}

impl TryFrom<u16> for QuestionType {
    type Error = ServerError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            252 => Ok(QuestionType::AXFR),
            253 => Ok(QuestionType::MAILB),
            254 => Ok(QuestionType::MAILA),
            255 => Ok(QuestionType::ALL),
            num => {
                let dns_type = DnsType::try_from(num)?;

                Ok(QuestionType::DnsType(dns_type))
            }
        }
    }
}

/// QCLASS fields appear in the question section of a query.  QCLASS values
/// are a superset of CLASS values; every CLASS is a valid QCLASS.  In
/// addition to CLASS values, the following QCLASSes are defined:
#[derive(Debug, Clone, Copy)]
pub enum QuestionClass {
    DnsClass(DnsClass),
    ALL,
}

impl Into<u16> for QuestionClass {
    fn into(self) -> u16 {
        match self {
            QuestionClass::DnsClass(dns_class) => dns_class.into(),
            QuestionClass::ALL => 255,
        }
    }
}

impl TryFrom<u16> for QuestionClass {
    type Error = ServerError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            255 => Ok(QuestionClass::ALL),
            num => {
                let dns_class = DnsClass::try_from(num)?;

                Ok(QuestionClass::DnsClass(dns_class))
            }
        }
    }
}

#[derive(Debug)]
pub struct QuestionsEncoder;

impl QuestionsEncoder {
    pub fn encode(&self, questions: &Vec<Question>) -> Bytes {
        let mut buf = BytesMut::new();

        for question in questions {
            buf.put(self.encode_question(question));
        }

        Bytes::from(buf)
    }

    fn encode_question(&self, question: &Question) -> Bytes {
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
pub struct QuestionsDecoder<'a> {
    buf: &'a mut Bytes,
    questions_count: u16,
    domain_names: QuestionDomainNames,
}

impl<'a> QuestionsDecoder<'a> {
    pub fn new(buf: &'a mut Bytes, questions_count: u16) -> Self {
        Self {
            buf,
            questions_count,
            domain_names: QuestionDomainNames::default(),
        }
    }

    pub fn decode(mut self) -> Result<Vec<Question>, ServerError> {
        let mut questions: Vec<Question> = Vec::with_capacity(self.questions_count as usize);

        for _ in 0..self.questions_count {
            let question = self.decode_question()?;

            questions.push(question);
        }

        Ok(questions)
    }

    fn decode_question(&mut self) -> Result<Question, ServerError> {
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
                .map_err(|err| ServerError::DecodeQuestion(err.to_string()))?;
            let domain_label = DomainLabel {
                pointer: Some(pointer_position),
                name: label.to_string(),
            };

            domain_name.add_label(domain_label);
        }

        let name = domain_name.to_string();
        let kind = QuestionType::try_from(self.buf.get_u16())?;
        let class = QuestionClass::try_from(self.buf.get_u16())?;

        self.domain_names.add_name(domain_name);

        Ok(Question { name, kind, class })
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
