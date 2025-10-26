use bytes::{BufMut, Bytes, BytesMut};

use crate::message::question::DnsQuestionDecoder;

use super::{
    answer::{DnsAnswer, DnsAnswerEncoder},
    constants::DNS_MESSAGE_PACKET_SIZE,
    error::DnsMessageError,
    header::{DnsHeader, DnsHeaderDecoder, DnsHeaderEncoder},
    question::{DnsQuestion, DnsQuestionClass, DnsQuestionEncoder, DnsQuestionType},
    types::{DnsClass, DnsType},
};

/// All communications in the DNS protocol are carried in a single format called a "message". Each message consists of 5 sections: header, question, answer, authority, and an additional space.
#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub question: DnsQuestion,
    pub answer: DnsAnswer,
}

pub struct DnsMessageEncoder;

impl DnsMessageEncoder {
    pub fn encode(message: &DnsMessage) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_MESSAGE_PACKET_SIZE);

        let header = DnsHeaderEncoder::encode(&message.header);
        buf.put(header);

        let question = DnsQuestionEncoder::encode(&message.question);
        buf.put(question);

        let answer = DnsAnswerEncoder::encode(&message.answer);
        buf.put(answer);

        Bytes::from(buf)
    }
}

pub struct DnsMessageDecoder;

impl DnsMessageDecoder {
    pub fn decode(buf: &[u8; DNS_MESSAGE_PACKET_SIZE]) -> Result<DnsMessage, DnsMessageError> {
        let mut buf = Bytes::copy_from_slice(buf);

        let header = DnsHeaderDecoder::decode(&mut buf)?;
        let question = DnsQuestionDecoder::decode(&mut buf)?;

        Ok(DnsMessage {
            header,
            question: DnsQuestion {
                name: question.name.clone(),
                kind: DnsQuestionType::DnsType(DnsType::A),
                class: DnsQuestionClass::DnsClass(DnsClass::IN),
            },
            answer: DnsAnswer {
                name: question.name.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 60,
                length: 4,
                data: "8.8.8.8".to_string(),
            },
        })
    }
}
