use std::convert::TryInto;
use std::fmt::Formatter;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use internet_checksum::Checksum;

pub enum IcmpType {
    EchoRequest,
    EchoReply,
    Unknown,
}

pub struct IcmpPacket<'a> {
    header0to3: &'a mut [u8; 4],
    header4to7: &'a mut [u8; 4],
    pub data: &'a  mut [u8],
}

impl<'a> From <&'a mut [u8]> for IcmpPacket<'a> {
    fn from(frame: &'a mut [u8]) -> IcmpPacket {
        let  (header0to3, rest) = frame.split_at_mut(4);
        let  (header4to7, data) = rest.split_at_mut(4);
        IcmpPacket {
            header0to3: header0to3.try_into().unwrap(),
            header4to7: header4to7.try_into().unwrap(),
            data
        }
    }
}

impl<'a> IcmpPacket<'a> {
    pub fn new(
        buffer: &'a mut [u8],
    ) -> IcmpPacket<'a> {
        // Zero out the header
        for i in &mut buffer[0..8] { *i = 0; }
        buffer.into()
    }

    pub fn icmp_type(&self) -> IcmpType {
        match self.header0to3[0] {
            0x00 => IcmpType::EchoReply,
            0x08 => IcmpType::EchoRequest,
            _ => IcmpType::Unknown,
        }
    }

    pub fn icmp_code(&self) -> u8 {
        self.header0to3[1]
    }

    pub fn checksum(&self) -> u16 {
        self.header0to3[2..4].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.header0to3[2..4].as_mut().write_u16::<NetworkEndian>(checksum).unwrap()
    }

    pub fn calculate_checksum(&mut self) {
        let mut checksum = Checksum::new();
        checksum.add_bytes(&self.header0to3[0..2]);
        checksum.add_bytes(&[0,0]);
        checksum.add_bytes(self.header4to7);
        checksum.add_bytes(self.data);
        self.header0to3[2..4].copy_from_slice(&checksum.checksum());
        println!("Checksum set to: {:x}", self.checksum());
    }

    pub fn rest_of_header(&self) -> [u8; 4] {
        self.header4to7.as_ref().try_into().unwrap()
    }

    pub fn set_rest_of_header(&mut self, data: &[u8; 4]) {
        self.header4to7.copy_from_slice(data);
    }

    /*pub fn data(&'a mut self) -> &'a mut [u8] {
        self.data
    }*/
}

impl<'a> std::fmt::Debug for IcmpPacket<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("IcmpPacket")
            .field("header0to3", &self.header0to3)
            .field("header4to7", &self.header4to7)
            .field("data", &format!("{} bytes of data", self.data.len()))
            .finish()
    }
}