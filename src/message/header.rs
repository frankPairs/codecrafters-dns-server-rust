use std::u16;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::message::error::ServerError;

use super::constants::DNS_MESSAGE_PACKET_SIZE;

// DNS header section is 12 bytes lenght
const DNS_HEADER_LEN: usize = 12;

/// The header contains information about the query/response.
/// It is 12 bytes long, and integers are encoded in big-endian format.
#[derive(Debug)]
pub struct Header {
    /// A random ID assigned to query packets. Response packets must reply with the same ID.
    pub id: u16,

    /// 1 for a reply packet, 0 for a question packet.
    pub query_indicator: bool,

    /// Specifies the kind of query in a message.
    pub operation_code: OperationCode,

    /// 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub auth_answer: bool,

    /// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub truncation: bool,

    /// Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_desired: bool,

    /// Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: bool,

    ///	Used by DNSSEC queries. At inception, it was reserved for future use.
    pub reserve: u8,

    /// Response code indicating the status of the response.
    pub code: ResponseCode,

    /// Number of questions in the Question section.
    pub question_count: u16,

    /// Number of records in the Answer section.
    pub answer_record_count: u16,

    /// Number of records in the Authority section.
    pub auth_record_count: u16,

    /// Number of records in the Additional section.
    pub additional_record_count: u16,
}

// A four bit field that specifies kind of query in this
// message.  This value is set by the originator of a query
// and copied into the response.  The values are:
//
// 0               a standard query (QUERY)
//
// 1               an inverse query (IQUERY)
//
// 2               a server status request (STATUS)
//
// 3-15            reserved for future use
#[derive(Debug, Clone, Copy)]
pub enum OperationCode {
    StandardQuery,
    InverseQuery,
    ServerStatusRequest,
    Reserve(u8),
}

impl Into<u8> for OperationCode {
    fn into(self) -> u8 {
        match self {
            OperationCode::StandardQuery => 0,
            OperationCode::InverseQuery => 1,
            OperationCode::ServerStatusRequest => 2,
            OperationCode::Reserve(num) => num,
        }
    }
}

impl TryFrom<u8> for OperationCode {
    type Error = ServerError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(OperationCode::StandardQuery),
            1 => Ok(OperationCode::InverseQuery),
            2 => Ok(OperationCode::ServerStatusRequest),
            3..=15 => Ok(OperationCode::Reserve(value)),
            num => Err(ServerError::DecodeHeader(format!(
                "{} is not a valid operation code",
                num
            ))),
        }
    }
}
// Response code - this 4 bit field is set as part of responses.  The values have the following interpretation:
//
//                 0               No error condition
//
//                 1               Format error - The name server was
//                                 unable to interpret the query.
//
//                 2               Server failure - The name server was
//                                 unable to process this query due to a
//                                 problem with the name server.
//
//                 3               Name Error - Meaningful only for
//                                 responses from an authoritative name
//                                 server, this code signifies that the
//                                 domain name referenced in the query does
//                                 not exist.
//
//                 4               Not Implemented - The name server does
//                                 not support the requested kind of query.
//
//                 5               Refused - The name server refuses to
//                                 perform the specified operation for
//                                 policy reasons.  For example, a name
//                                 server may not wish to provide the
//                                 information to the particular requester,
//                                 or a name server may not wish to perform
//                                 a particular operation (e.g., zone
//                                 transfer) for particular data.
//
//                 6-15            Reserved for future use.
#[derive(Debug, Clone, Copy)]
pub enum ResponseCode {
    NoErrorCondition,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl Into<u8> for ResponseCode {
    fn into(self) -> u8 {
        match self {
            ResponseCode::NoErrorCondition => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Reserved(num) => num,
        }
    }
}

impl TryFrom<u8> for ResponseCode {
    type Error = ServerError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ResponseCode::NoErrorCondition),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServerFailure),
            3 => Ok(ResponseCode::NameError),
            4 => Ok(ResponseCode::NotImplemented),
            5 => Ok(ResponseCode::Refused),
            6..=15 => Ok(ResponseCode::Reserved(value)),
            num => Err(ServerError::DecodeHeader(format!(
                "{} is not a valid response code",
                num
            ))),
        }
    }
}

pub struct HeaderEncoder;

impl HeaderEncoder {
    pub fn encode(header: &Header) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_MESSAGE_PACKET_SIZE);

        buf.put_u16(header.id);

        let mut third_byte: u8 = 0;

        if header.query_indicator {
            third_byte = third_byte | 1 << 7;
        }

        // It shifts the bits from operation code u8 3 positions because we want to keep the first
        // bit to 0 as it represents the query indicator
        //
        // Example:
        // let mut third_byte_with_query_indicator = b"1000_0000";
        // let operation_code_mask = b"0000_1111";
        //
        // assert!(third_byte_with_query_indicator | operation_code_mask, b"1111_1000");
        let operation_code_num: u8 = header.operation_code.into();
        let operation_code_mask = operation_code_num << 3;
        third_byte = third_byte | operation_code_mask;

        if header.auth_answer {
            third_byte = third_byte | 1 << 2;
        }

        if header.truncation {
            third_byte = third_byte | 1 << 1;
        }

        if header.recursion_desired {
            third_byte = third_byte | 1 << 0;
        }

        buf.put_u8(third_byte);

        let mut fourth_byte: u8 = 0;

        if header.recursion_available {
            fourth_byte = fourth_byte | 1 << 7;
        }

        // Here we do not need to shift any bit as we did with the operation code because the first
        // four bits are already taken by the recursion available (1 bit) and the reserved (3 bits)
        let response_code_mask: u8 = header.code.into();

        fourth_byte = fourth_byte | response_code_mask;

        buf.put_u8(fourth_byte);

        buf.put_u16(header.question_count);
        buf.put_u16(header.answer_record_count);
        buf.put_u16(header.auth_record_count);
        buf.put_u16(header.additional_record_count);

        Bytes::from(buf)
    }
}

pub struct HeaderDecoder;

impl HeaderDecoder {
    pub fn decode(buf: &mut Bytes) -> Result<Header, ServerError> {
        let mut buf = buf.copy_to_bytes(DNS_HEADER_LEN);

        let id = buf.get_u16();

        let third_byte = buf.get_u8();

        let query_indicator = third_byte & 0b0000_0001 > 0;

        let operation_code_mask = (third_byte & 0b0111_1000) >> 3;
        let operation_code = OperationCode::try_from(operation_code_mask)?;

        let auth_answer = third_byte & 0b0000_0100 > 0;
        let truncation = third_byte & 0b0000_0010 > 0;
        let recursion_desired = third_byte & 0b0000_0001 > 0;

        let fourth_byte = buf.get_u8();

        let recursion_available = fourth_byte & 0b1000_0000 > 0;

        let code_mask = fourth_byte >> 4;
        let code = ResponseCode::try_from(code_mask)?;

        let question_count = buf.get_u16();
        let answer_record_count = buf.get_u16();
        let auth_record_count = buf.get_u16();
        let additional_record_count = buf.get_u16();

        Ok(Header {
            id,
            query_indicator,
            operation_code,
            auth_answer,
            truncation,
            recursion_desired,
            recursion_available,
            reserve: 0,
            code,
            question_count,
            answer_record_count,
            auth_record_count,
            additional_record_count,
        })
    }
}
