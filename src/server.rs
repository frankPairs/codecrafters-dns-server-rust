use std::{
    net::{SocketAddr, UdpSocket},
    str::FromStr,
};

use crate::error::ServerError;
use crate::message::{
    answer::{Answer, AnswersBuilder},
    constants::DNS_MESSAGE_PACKET_SIZE,
    header::{Header, OperationCode, ResponseCode},
    message::{Message, MessageDecoder, MessageEncoder},
};

pub struct DnsServer {
    udp_socket: UdpSocket,
}

impl DnsServer {
    pub fn bind(addr: &str) -> std::io::Result<DnsServer> {
        let socket = UdpSocket::bind(addr)?;

        Ok(Self { udp_socket: socket })
    }

    pub fn listen(self, resolver_addr: Option<&str>) -> Result<(), ServerError> {
        let mut buf = [0; DNS_MESSAGE_PACKET_SIZE];

        loop {
            match self.udp_socket.recv_from(&mut buf) {
                Ok((_, source)) => {
                    let query = MessageDecoder::decode(&buf).unwrap();

                    let answers: Vec<Answer> = match &resolver_addr {
                        Some(addr) => {
                            let addr = SocketAddr::from_str(&addr.to_string())
                                .expect("Invalid resolver address");

                            AnswersBuilder::build_answers_from_resolver(
                                &query,
                                &self.udp_socket,
                                &addr,
                            )
                            .unwrap()
                        }
                        None => AnswersBuilder::build_answers(&query).unwrap(),
                    };

                    let response_message = Message {
                        header: Header {
                            id: query.header.id,
                            query_indicator: true,
                            operation_code: query.header.operation_code,
                            auth_answer: false,
                            truncation: false,
                            recursion_desired: query.header.recursion_desired,
                            recursion_available: false,
                            reserve: 0,
                            code: if matches!(
                                query.header.operation_code,
                                OperationCode::StandardQuery
                            ) {
                                ResponseCode::NoErrorCondition
                            } else {
                                ResponseCode::NotImplemented
                            },
                            question_count: query.questions.len() as u16,
                            answer_record_count: answers.len() as u16,
                            auth_record_count: 0,
                            additional_record_count: 0,
                        },
                        questions: query.questions,
                        answers,
                    };

                    let response = MessageEncoder::encode(&response_message);

                    self.udp_socket
                        .send_to(&response, source)
                        .expect("Failed to send response");
                }
                Err(e) => {
                    eprintln!("Error receiving data: {}", e);
                    break Ok(());
                }
            }
        }
    }
}
