use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsMessageError {
    #[error("DecodeHeader Error: {0}")]
    DecodeHeader(String),
    #[error("EncodeHeader Error: {0}")]
    EncodeHeader(String),
    #[error("InvalidOperationCode Error: {0}")]
    InvalidOperationCode(String),
    #[error("InvalidResponseCode Error: {0}")]
    InvalidResponseCode(String),
    #[error("InvalidDnsType Error: {0}")]
    InvalidDnsType(String),
    #[error("InvalidQuestionType Error: {0}")]
    InvalidQuestionType(String),
    #[error("InvalidQuestionClass Error: {0}")]
    InvalidQuestionClass(String),
}
