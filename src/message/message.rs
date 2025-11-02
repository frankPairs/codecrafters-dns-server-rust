use bytes::{BufMut, Bytes, BytesMut};

use crate::message::question::DnsQuestionsDecoder;

use super::{
    answer::{DnsAnswer, DnsAnswersEncoder},
    constants::DNS_MESSAGE_PACKET_SIZE,
    error::DnsMessageError,
    header::{DnsHeader, DnsHeaderDecoder, DnsHeaderEncoder},
    question::{DnsQuestion, DnsQuestionsEncoder},
    types::{DnsClass, DnsType},
};

/// All communications in the DNS protocol are carried in a single format called a "message". Each message consists of 5 sections: header, question, answer, authority, and an additional space.
#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

pub struct DnsMessageEncoder;

impl DnsMessageEncoder {
    pub fn encode(message: &DnsMessage) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_MESSAGE_PACKET_SIZE);

        let header = DnsHeaderEncoder::encode(&message.header);
        buf.put(header);

        let questions_encoder = DnsQuestionsEncoder;
        let questions = questions_encoder.encode(&message.questions);
        buf.put(questions);

        let answers_encoder = DnsAnswersEncoder;
        let answers = answers_encoder.encode(&message.answers);
        buf.put(answers);

        Bytes::from(buf)
    }
}

pub struct DnsMessageDecoder;

impl DnsMessageDecoder {
    pub fn decode(buf: &[u8; DNS_MESSAGE_PACKET_SIZE]) -> Result<DnsMessage, DnsMessageError> {
        let mut buf = Bytes::copy_from_slice(buf);

        let header = DnsHeaderDecoder::decode(&mut buf)?;

        let questions_decoder = DnsQuestionsDecoder::new(&mut buf, header.question_count);
        let questions = questions_decoder.decode()?;

        let answers: Vec<DnsAnswer> = questions
            .iter()
            .map(|question| DnsAnswer {
                name: question.name.to_string(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 60,
                length: 4,
                data: "8.8.8.8".to_string(),
            })
            .collect();

        Ok(DnsMessage {
            header,
            questions,
            answers,
        })
    }
}
