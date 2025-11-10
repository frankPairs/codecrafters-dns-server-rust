use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("DecodeHeader Error: {0}")]
    DecodeHeader(String),
    #[error("DecodeQuestion Error: {0}")]
    DecodeQuestion(String),
    #[error("DecodeAnswer Error: {0}")]
    DecodeAnswer(String),
    #[error("InvalidDnsType Error: {0}")]
    InvalidDnsType(String),
    #[error("InvalidDnsClass Error: {0}")]
    InvalidDnsClass(String),
    #[error("ForwardedServer Error: {0}")]
    ForwardedServer(String),
}
