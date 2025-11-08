use std::net::{SocketAddr, UdpSocket};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::message::{
    error::ServerError,
    header::Header,
    message::{Message, MessageDecoder, MessageEncoder},
    types::{DomainLabel, DomainName},
};

use super::{
    constants::DNS_MESSAGE_PACKET_SIZE,
    types::{DnsClass, DnsType},
};

/// The answer section contains RRs that answer the question
#[derive(Debug)]
pub struct Answer {
    /// The domain name encoded as a sequence of labels.
    pub name: String,
    pub kind: DnsType,
    pub class: DnsClass,
    ///	The duration in seconds a record can be cached before requerying.
    pub ttl: u32,
    /// Length of the RDATA field in bytes.
    pub length: u16,
    /// Data specific to the record type.
    pub data: String,
}

pub struct AnswersEncoder;

impl AnswersEncoder {
    pub fn encode(&self, answers: &Vec<Answer>) -> Bytes {
        let mut buf = BytesMut::new();

        for answer in answers {
            buf.put(self.encode_answer(answer));
        }

        Bytes::from(buf)
    }

    fn encode_answer(&self, answer: &Answer) -> Bytes {
        let mut buf = BytesMut::new();
        let mut encoded_name = BytesMut::new();
        let answer_name_parts = answer.name.split(".");

        for part in answer_name_parts {
            let label_length: u8 = part.len() as u8;

            encoded_name.put_u8(label_length);
            encoded_name.put(part.as_bytes());
        }

        encoded_name.put_u8(0);

        buf.put(encoded_name);

        buf.put_u16(answer.kind.into());

        buf.put_u16(answer.class.into());

        buf.put_u32(answer.ttl);

        buf.put_u16(answer.length);

        let answer_data_parts = answer.data.split(".");

        // TODO: Check if answer.data contains just 4 parts. Otherwises, throw an error.

        let mut encoded_data = BytesMut::new();

        for part in answer_data_parts {
            let value = u8::from_str_radix(part, 10).expect("Error when encoding answer data");

            encoded_data.put_u8(value);
        }

        buf.put(encoded_data);

        Bytes::from(buf)
    }
}
pub struct AnswersDecoder<'a> {
    buf: &'a mut Bytes,
    answers_count: u16,
}

impl<'a> AnswersDecoder<'a> {
    pub fn new(buf: &'a mut Bytes, answers_count: u16) -> Self {
        Self { buf, answers_count }
    }

    pub fn decode(mut self) -> Result<Vec<Answer>, ServerError> {
        let mut answers: Vec<Answer> = Vec::with_capacity(self.answers_count as usize);

        for _ in 0..self.answers_count {
            let answer = self.decode_answer()?;

            answers.push(answer);
        }

        Ok(answers)
    }

    pub fn decode_answer(&mut self) -> Result<Answer, ServerError> {
        let mut domain_name = DomainName::default();

        loop {
            let label_length = self.buf.get_u8();

            if label_length == 0 {
                break;
            }

            let bytes = self.buf.copy_to_bytes(label_length as usize);
            let label = std::str::from_utf8(&bytes[..])
                .map_err(|err| ServerError::DecodeAnswer(err.to_string()))?;

            domain_name.add_label(DomainLabel {
                pointer: None,
                name: label.to_string(),
            });
        }

        let kind = DnsType::try_from(self.buf.get_u16())?;
        let class = DnsClass::try_from(self.buf.get_u16())?;
        let ttl = self.buf.get_u32();
        let length = self.buf.get_u16();

        let mut data: Vec<String> = Vec::new();

        for _ in 0..length {
            let value = self.buf.get_u8();

            data.push(value.to_string());
        }

        Ok(Answer {
            name: domain_name.to_string(),
            kind,
            class,
            ttl,
            length,
            data: data.join("."),
        })
    }
}

pub struct AnswersBuilder;

impl AnswersBuilder {
    pub fn build_answers(query: &Message) -> Result<Vec<Answer>, ServerError> {
        Ok(query
            .questions
            .iter()
            .map(|question| Answer {
                name: question.name.to_string(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 60,
                length: 4,
                data: "8.8.8.8".to_string(),
            })
            .collect())
    }

    pub fn build_answers_from_resolver(
        query: &Message,
        socket: &UdpSocket,
        addr: &SocketAddr,
    ) -> Result<Vec<Answer>, ServerError> {
        let mut answers: Vec<Answer> = Vec::with_capacity(query.header.question_count as usize);

        for question in &query.questions {
            let message = Message {
                header: Header {
                    question_count: 1,
                    query_indicator: false,
                    ..query.header
                },
                questions: vec![question.clone()],
                answers: Vec::new(),
            };

            let encoded_message = MessageEncoder::encode(&message);

            // Sent a message to the forwarded server with one question
            socket
                .send_to(&encoded_message, addr)
                .map_err(|err| ServerError::ForwardedServer(err.to_string()))?;

            let mut buf = [0; DNS_MESSAGE_PACKET_SIZE];

            // Receive a message from the forwarded server
            socket
                .recv_from(&mut buf)
                .map_err(|err| ServerError::ForwardedServer(err.to_string()))?;

            let forwarded_message = MessageDecoder::decode(&buf)?;

            for answer in forwarded_message.answers {
                answers.push(answer);
            }
        }

        Ok(answers)
    }
}
