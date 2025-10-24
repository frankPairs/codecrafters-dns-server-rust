use bytes::{BufMut, Bytes, BytesMut};

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
    pub fn decode(data: &[u8; DNS_MESSAGE_PACKET_SIZE]) -> Result<DnsMessage, DnsMessageError> {
        let buf = Bytes::copy_from_slice(data);

        let header_data = buf.get(0..12).ok_or(DnsMessageError::DecodeHeader(
            "Message does not contain header data".to_string(),
        ))?;

        let header = DnsHeaderDecoder::decode(&header_data)?;

        Ok(DnsMessage {
            header,
            question: DnsQuestion {
                name: "codecrafters.io".to_string(),
                kind: DnsQuestionType::ALL,
                class: DnsQuestionClass::ALL,
            },
            answer: DnsAnswer {
                name: "codecrafters.io".to_string(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 60,
                length: 4,
                data: "8.8.8.8".to_string(),
            },
        })
    }
}
