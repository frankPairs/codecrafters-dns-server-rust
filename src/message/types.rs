use super::error::DnsMessageError;

/// TYPE fields are used in resource records
#[derive(Debug, Clone, Copy)]
pub enum DnsType {
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
}

impl Into<u16> for DnsType {
    fn into(self) -> u16 {
        match self {
            DnsType::A => 1,
            DnsType::NS => 2,
            DnsType::MD => 3,
            DnsType::MF => 4,
            DnsType::CNAME => 5,
            DnsType::SOA => 6,
            DnsType::MB => 7,
            DnsType::MG => 8,
            DnsType::MR => 9,
            DnsType::NULL => 10,
            DnsType::WKS => 11,
            DnsType::PTR => 12,
            DnsType::HINFO => 13,
            DnsType::MINFO => 14,
            DnsType::MX => 15,
            DnsType::TXT => 16,
        }
    }
}

/// CLASS fields appear in resource records.
#[derive(Debug, Clone, Copy)]
pub enum DnsClass {
    /// 1 the Internet
    IN,
    /// 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS,
    /// 3 the CHAOS class
    CH,
    /// 4 Hesiod [Dyer 87]
    HS,
}

impl Into<u16> for DnsClass {
    fn into(self) -> u16 {
        match self {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
        }
    }
}
