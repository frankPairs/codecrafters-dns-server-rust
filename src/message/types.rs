use crate::error::ServerError;

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

impl TryFrom<u16> for DnsType {
    type Error = ServerError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsType::A),
            2 => Ok(DnsType::NS),
            3 => Ok(DnsType::MD),
            4 => Ok(DnsType::MF),
            5 => Ok(DnsType::CNAME),
            6 => Ok(DnsType::SOA),
            7 => Ok(DnsType::MB),
            8 => Ok(DnsType::MG),
            9 => Ok(DnsType::MR),
            10 => Ok(DnsType::NULL),
            11 => Ok(DnsType::WKS),
            12 => Ok(DnsType::PTR),
            13 => Ok(DnsType::HINFO),
            14 => Ok(DnsType::MINFO),
            15 => Ok(DnsType::MX),
            16 => Ok(DnsType::TXT),
            num => Err(ServerError::InvalidDnsType(format!(
                "{} is not a valid DNS type",
                num
            ))),
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

impl TryFrom<u16> for DnsClass {
    type Error = ServerError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsClass::IN),
            2 => Ok(DnsClass::CS),
            3 => Ok(DnsClass::CH),
            4 => Ok(DnsClass::HS),
            num => Err(ServerError::InvalidDnsClass(format!(
                "{} is not a valid DNS class",
                num
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainLabel {
    pub name: String,
    pub pointer: Option<usize>,
}

impl std::borrow::Borrow<str> for DomainLabel {
    fn borrow(&self) -> &str {
        self.name.as_str()
    }
}

#[derive(Debug, Default)]
pub struct DomainName {
    labels: Vec<DomainLabel>,
}

impl DomainName {
    pub fn get_labels(&self) -> &[DomainLabel] {
        &self.labels
    }

    pub fn add_label(&mut self, new_label: DomainLabel) {
        self.labels.push(new_label);
    }

    pub fn as_slice(&self, start_index: usize) -> &[DomainLabel] {
        &self.labels[start_index..]
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.labels.join(".");

        write!(f, "{}", name)
    }
}
