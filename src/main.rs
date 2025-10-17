use bytes::{BufMut, Bytes, BytesMut};
use std::net::UdpSocket;

/// Conventionally, DNS packets are sent using UDP transport and are limited to 512 bytes
const DNS_PACKET_SIZE: usize = 512;

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
/// All communications in the DNS protocol are carried in a single format called a "message". Each message consists of 5 sections: header, question, answer, authority, and an additional space.
#[derive(Debug)]
struct DnsMessage {
    header: DnsHeader,
}

struct DnsMessageEncoder;

impl DnsMessageEncoder {
    fn encode(message: &DnsMessage) -> Bytes {
        let mut buf = BytesMut::with_capacity(DNS_PACKET_SIZE);

        let header = DnsHeaderEncoder::encode(&message.header);
        buf.put(header);

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
                        question_count: 0,
                        answer_record_count: 0,
                        auth_record_count: 0,
                        additional_record_count: 0,
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
