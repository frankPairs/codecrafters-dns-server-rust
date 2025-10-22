use bytes::{BufMut, Bytes, BytesMut};

use super::types::{DnsClass, DnsType};

/// The answer section contains RRs that answer the question
#[derive(Debug)]
pub struct DnsAnswer {
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

pub struct DnsAnswerEncoder;

impl DnsAnswerEncoder {
    pub fn encode(answer: &DnsAnswer) -> Bytes {
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
