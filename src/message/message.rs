use bytes::{BufMut, Bytes, BytesMut};

use super::{
    answer::{Answer, AnswersDecoder, AnswersEncoder},
    constants::DNS_MESSAGE_PACKET_SIZE,
    header::{Header, HeaderDecoder, HeaderEncoder},
    question::{Question, QuestionsDecoder, QuestionsEncoder},
};
use crate::error::ServerError;

/// All communications in the DNS protocol are carried in a single format called a "message". Each message consists of 5 sections: header, question, answer, authority, and an additional space.
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

pub struct MessageEncoder;

impl MessageEncoder {
    pub fn encode(message: &Message) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_MESSAGE_PACKET_SIZE);

        let header = HeaderEncoder::encode(&message.header);
        buf.put(header);

        if !&message.questions.is_empty() {
            let questions_encoder = QuestionsEncoder;
            let questions = questions_encoder.encode(&message.questions);

            buf.put(questions);
        }

        if !&message.answers.is_empty() {
            let answers_encoder = AnswersEncoder;
            let answers = answers_encoder.encode(&message.answers);

            buf.put(answers);
        }

        Bytes::from(buf)
    }
}

pub struct MessageDecoder;

impl MessageDecoder {
    pub fn decode(buf: &[u8; DNS_MESSAGE_PACKET_SIZE]) -> Result<Message, ServerError> {
        let mut buf = Bytes::copy_from_slice(buf);

        let header = HeaderDecoder::decode(&mut buf)?;
        let mut questions = Vec::with_capacity(header.question_count as usize);
        let mut answers = Vec::with_capacity(header.answer_record_count as usize);

        if header.question_count > 0 {
            let questions_decoder = QuestionsDecoder::new(&mut buf, header.question_count);
            let decoded_questions = questions_decoder.decode()?;

            questions = decoded_questions;
        }

        if header.answer_record_count > 0 {
            let answers_decoder = AnswersDecoder::new(&mut buf, header.answer_record_count);
            let decoded_answers = answers_decoder.decode()?;

            answers = decoded_answers;
        }
        Ok(Message {
            header,
            questions,
            answers,
        })
    }
}
