use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsMessageError {
    #[error("InvalidDnsType Error: {0}")]
    InvalidDnsType(String),
    #[error("InvalidQuestionType Error: {0}")]
    InvalidQuestionType(String),
    #[error("InvalidQuestionClass Error: {0}")]
    InvalidQuestionClass(String),
}
