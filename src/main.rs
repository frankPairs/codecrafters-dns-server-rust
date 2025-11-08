mod message;

use std::{
    env,
    net::{SocketAddr, UdpSocket},
    str::FromStr,
};

use crate::message::{
    answer::{Answer, AnswersBuilder},
    constants::DNS_MESSAGE_PACKET_SIZE,
    header::{Header, OperationCode, ResponseCode},
    message::{Message, MessageDecoder, MessageEncoder},
};

const RESOLVER_ARG_NAME: &str = "--resolver";

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; DNS_MESSAGE_PACKET_SIZE];
    let mut cli_args = env::args();

    let resolver_addr = cli_args
        .nth(1)
        .and_then(|arg_name| {
            if arg_name == RESOLVER_ARG_NAME {
                Some(arg_name)
            } else {
                None
            }
        })
        .and_then(|_| cli_args.next());

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let query = MessageDecoder::decode(&buf).unwrap();

                let answers: Vec<Answer> = match &resolver_addr {
                    Some(addr) => {
                        let addr =
                            SocketAddr::from_str(addr.as_str()).expect("Invalid resolver address");

                        AnswersBuilder::build_answers_from_resolver(&query, &udp_socket, &addr)
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
                        code: if matches!(query.header.operation_code, OperationCode::StandardQuery)
                        {
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
