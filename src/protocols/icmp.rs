use std::convert::TryInto;
use std::fmt::Formatter;
use byteorder::{NetworkEndian,ReadBytesExt};

pub struct IcmpPacket<'a> {
    header: &'a mut [u8; 8],
    data: &'a  mut [u8],
}

impl<'a> From <&'a mut [u8]> for IcmpPacket<'a> {
    fn from(frame: &'a mut [u8]) -> IcmpPacket {
        let  (header, data) = frame.split_at_mut(8);
        IcmpPacket {
            header: header.try_into().unwrap(),
            data
        }
    }
}

enum IcmpType {
    EchoRequest,
    EchoReply,
    Unknown,
}

impl<'a> IcmpPacket<'a> {
    fn icmp_type(&self) -> IcmpType {
        match self.header[0] {
            0x00 => IcmpType::EchoReply,
            0x08 => IcmpType::EchoRequest,
            _ => IcmpType::Unknown,
        }
    }

    fn icmp_code(&self) -> u8 {
        self.header[1]
    }

    fn checksum(&self) -> u16 {
        self.header[2..4].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    fn rest_of_header(&self) -> u32 {
        self.header[4..8].as_ref().read_u32::<NetworkEndian>().unwrap()
    }
}

impl<'a> std::fmt::Debug for IcmpPacket<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("IcmpPacket")
            .field("header", &self.header)
            .field("data", &format!("{} bytes of data", self.data.len()))
            .finish()
    }
}