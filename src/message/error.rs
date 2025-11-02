use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsMessageError {
    #[error("DecodeHeader Error: {0}")]
    DecodeHeader(String),
    #[error("DecodeQuestion Error: {0}")]
    DecodeQuestion(String),
    #[error("InvalidDnsType Error: {0}")]
    InvalidDnsType(String),
    #[error("InvalidDnsClass Error: {0}")]
    InvalidDnsClass(String),
}
