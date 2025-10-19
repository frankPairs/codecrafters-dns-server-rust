use bytes::{BufMut, Bytes, BytesMut};
use std::{fmt::format, net::UdpSocket};
use thiserror::Error;

/// Conventionally, DNS packets are sent using UDP transport and are limited to 512 bytes
const DNS_PACKET_SIZE: usize = 512;

#[derive(Debug, Error)]
enum DnsMessageError {
    #[error("InvalidQuestionType Error: {0}")]
    InvalidQuestionType(String),
    #[error("InvalidQuestionClass Error: {0}")]
    InvalidQuestionClass(String),
}

/// The header contains information about the query/response.
/// It is 12 bytes long, and integers are encoded in big-endian format.
#[derive(Debug)]
struct DnsHeader {
    /// A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,

    /// 1 for a reply packet, 0 for a question packet.
    query_indicator: bool,

    /// Specifies the kind of query in a message.
    operation_code: DnsOperationCode,

    /// 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    auth_answer: bool,

    /// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    truncation: bool,

    /// Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    recursion_desired: bool,

    /// Server sets this to 1 to indicate that recursion is available.
    recursion_available: bool,

    ///	Used by DNSSEC queries. At inception, it was reserved for future use.
    reserve: u8,

    /// Response code indicating the status of the response.
    code: DnsResponseCode,

    /// Number of questions in the Question section.
    question_count: u16,

    /// Number of records in the Answer section.
    answer_record_count: u16,

    /// Number of records in the Authority section.
    auth_record_count: u16,

    /// Number of records in the Additional section.
    additional_record_count: u16,
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
enum DnsOperationCode {
    StandardQuery,
    InverseQuery,
    ServerStatusRequest,
    Reserve,
}

impl Into<u8> for DnsOperationCode {
    fn into(self) -> u8 {
        match self {
            DnsOperationCode::StandardQuery => 0,
            DnsOperationCode::InverseQuery => 1,
            DnsOperationCode::ServerStatusRequest => 2,
            DnsOperationCode::Reserve => 15,
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
enum DnsResponseCode {
    NoErrorCondition,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved,
}

impl Into<u8> for DnsResponseCode {
    fn into(self) -> u8 {
        match self {
            DnsResponseCode::NoErrorCondition => 0,
            DnsResponseCode::FormatError => 1,
            DnsResponseCode::ServerFailure => 2,
            DnsResponseCode::NameError => 3,
            DnsResponseCode::NotImplemented => 4,
            DnsResponseCode::Refused => 5,
            DnsResponseCode::Reserved => 15,
        }
    }
}
/// The question section contains a list of questions (usually just 1) that the sender wants to ask the receiver. This section is present in both query and reply packets.
#[derive(Debug)]
struct DnsQuestion {
    /// A domain name, represented as a sequence of "labels" (more on this below)
    name: String,
    kind: DnsQuestionKind,
    class: DnsQuestionClass,
}
/// QTYPE fields appear in the question part of a query.  QTYPES are a
/// superset of TYPEs, hence all TYPEs are valid QTYPEs.
#[derive(Debug, Clone, Copy)]
enum DnsQuestionKind {
    /// 1 a host address
    A,
    /// 2 an authoritative name server
    NS,
    /// 3 a mail destination (Obsolete - use MX)
    MD,
    /// 4 a mail forwarder (Obsolete - use MX)
    MF,
    /// 5 the canonical name for an alias
    CNAME,
    /// 6 marks the start of a zone of authority
    SOA,
    /// 7 a mailbox domain name (EXPERIMENTAL)
    MB,
    /// 8 a mail group member (EXPERIMENTAL)
    MG,
    /// 9 a mail rename domain name (EXPERIMENTAL)
    MR,
    /// 10 a null RR (EXPERIMENTAL)
    NULL,
    /// 11 a well known service description
    WKS,
    /// 12 a domain name pointer
    PTR,
    /// 13 host information
    HINFO,
    /// 14 mailbox or mail list information
    MINFO,
    /// 15 mail exchange
    MX,
    /// 16 text strings
    TXT,
    /// 252 A request for a transfer of an entire zone
    AXFR,
    /// 253 A request for mailbox-related records (MB, MG or MR)
    MAILB,
    /// 254 A request for mail agent RRs (Obsolete - see MX)
    MAILA,
    /// 255 A request for all records
    ALL,
}

impl Into<u16> for DnsQuestionKind {
    fn into(self) -> u16 {
        match self {
            DnsQuestionKind::A => 1,
            DnsQuestionKind::NS => 2,
            DnsQuestionKind::MD => 3,
            DnsQuestionKind::MF => 4,
            DnsQuestionKind::CNAME => 5,
            DnsQuestionKind::SOA => 6,
            DnsQuestionKind::MB => 7,
            DnsQuestionKind::MG => 8,
            DnsQuestionKind::MR => 9,
            DnsQuestionKind::NULL => 10,
            DnsQuestionKind::WKS => 11,
            DnsQuestionKind::PTR => 12,
            DnsQuestionKind::HINFO => 13,
            DnsQuestionKind::MINFO => 14,
            DnsQuestionKind::MX => 15,
            DnsQuestionKind::TXT => 16,
            DnsQuestionKind::AXFR => 252,
            DnsQuestionKind::MAILB => 253,
            DnsQuestionKind::MAILA => 254,
            DnsQuestionKind::ALL => 255,
        }
    }
}

impl TryFrom<u16> for DnsQuestionKind {
    type Error = DnsMessageError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsQuestionKind::A),
            2 => Ok(DnsQuestionKind::NS),
            3 => Ok(DnsQuestionKind::MD),
            4 => Ok(DnsQuestionKind::MF),
            5 => Ok(DnsQuestionKind::CNAME),
            6 => Ok(DnsQuestionKind::SOA),
            7 => Ok(DnsQuestionKind::MB),
            8 => Ok(DnsQuestionKind::MG),
            9 => Ok(DnsQuestionKind::MR),
            10 => Ok(DnsQuestionKind::NULL),
            11 => Ok(DnsQuestionKind::WKS),
            12 => Ok(DnsQuestionKind::PTR),
            13 => Ok(DnsQuestionKind::HINFO),
            14 => Ok(DnsQuestionKind::MINFO),
            15 => Ok(DnsQuestionKind::MX),
            16 => Ok(DnsQuestionKind::TXT),
            252 => Ok(DnsQuestionKind::AXFR),
            253 => Ok(DnsQuestionKind::MAILB),
            254 => Ok(DnsQuestionKind::MAILA),
            255 => Ok(DnsQuestionKind::ALL),
            num => Err(DnsMessageError::InvalidQuestionType(format!(
                "{} is not a valid question type",
                num
            ))),
        }
    }
}

/// QCLASS fields appear in the question section of a query.  QCLASS values
/// are a superset of CLASS values; every CLASS is a valid QCLASS.  In
/// addition to CLASS values, the following QCLASSes are defined:
#[derive(Debug, Clone, Copy)]
enum DnsQuestionClass {
    /// 1 the Internet
    IN,
    /// 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS,
    /// 3 the CHAOS class
    CH,
    /// 4 Hesiod [Dyer 87]
    HS,
}

impl Into<u16> for DnsQuestionClass {
    fn into(self) -> u16 {
        match self {
            DnsQuestionClass::IN => 1,
            DnsQuestionClass::CS => 2,
            DnsQuestionClass::CH => 3,
            DnsQuestionClass::HS => 4,
        }
    }
}
impl TryFrom<u16> for DnsQuestionClass {
    type Error = DnsMessageError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsQuestionClass::IN),
            2 => Ok(DnsQuestionClass::CS),
            3 => Ok(DnsQuestionClass::CH),
            4 => Ok(DnsQuestionClass::HS),
            num => Err(DnsMessageError::InvalidQuestionClass(format!(
                "{} is not a valid question class",
                num
            ))),
        }
    }
}

/// All communications in the DNS protocol are carried in a single format called a "message". Each message consists of 5 sections: header, question, answer, authority, and an additional space.
#[derive(Debug)]
struct DnsMessage {
    header: DnsHeader,
    question: DnsQuestion,
}

struct DnsMessageEncoder;

impl DnsMessageEncoder {
    fn encode(message: &DnsMessage) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_PACKET_SIZE);

        let header = DnsHeaderEncoder::encode(&message.header);
        buf.put(header);

        let question = DnsQuestionEncoder::encode(&message.question);
        buf.put(question);

        Bytes::from(buf)
    }
}

struct DnsHeaderEncoder;

impl DnsHeaderEncoder {
    fn encode(header: &DnsHeader) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_PACKET_SIZE);

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

struct DnsQuestionEncoder;

impl DnsQuestionEncoder {
    fn encode(question: &DnsQuestion) -> Bytes {
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

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; DNS_PACKET_SIZE];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let message = DnsMessage {
                    header: DnsHeader {
                        id: 1234,
                        query_indicator: true,
                        operation_code: DnsOperationCode::StandardQuery,
                        auth_answer: false,
                        truncation: false,
                        recursion_desired: false,
                        recursion_available: false,
                        reserve: 0,
                        code: DnsResponseCode::NoErrorCondition,
                        question_count: 1,
                        answer_record_count: 0,
                        auth_record_count: 0,
                        additional_record_count: 0,
                    },
                    question: DnsQuestion {
                        name: "codecrafters.io".to_string(),
                        kind: DnsQuestionKind::A,
                        class: DnsQuestionClass::IN,
                    },
                };
                println!("Received {} bytes from {}", size, source);

                let response = DnsMessageEncoder::encode(&message);

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
