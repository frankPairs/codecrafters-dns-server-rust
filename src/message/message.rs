use bytes::{BufMut, Bytes, BytesMut};

use super::{
    answer::{DnsAnswer, DnsAnswerEncoder},
    constants::DNS_MESSAGE_PACKET_SIZE,
    header::{DnsHeader, DnsHeaderEncoder},
    question::{DnsQuestion, DnsQuestionEncoder},
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
