mod message;

use std::net::UdpSocket;

use crate::message::{
    answer::DnsAnswer,
    constants::DNS_MESSAGE_PACKET_SIZE,
    header::{DnsHeader, DnsOperationCode, DnsResponseCode},
    message::{DnsMessage, DnsMessageEncoder},
    question::{DnsQuestion, DnsQuestionClass, DnsQuestionType},
    types::{DnsClass, DnsType},
};

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; DNS_MESSAGE_PACKET_SIZE];

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
                        answer_record_count: 1,
                        auth_record_count: 0,
                        additional_record_count: 0,
                    },
                    question: DnsQuestion {
                        name: "codecrafters.io".to_string(),
                        kind: DnsQuestionType::DnsType(DnsType::A),
                        class: DnsQuestionClass::DnsClass(DnsClass::IN),
                    },
                    answer: DnsAnswer {
                        name: "codecrafters.io".to_string(),
                        kind: DnsType::A,
                        class: DnsClass::IN,
                        ttl: 60,
                        length: 4,
                        data: "8.8.8.8".to_string(),
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
