use std::convert::TryInto;
use std::fmt;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::fmt::{Formatter, Debug};
use crate::protocols::icmp::IcmpPacket;
use std::mem::take;
use internet_checksum::Checksum;

// Custom fmt::Debug
#[derive(PartialEq)]
pub struct Ipv4Address<'a> {
    ip: &'a mut [u8; 4],
}

impl<'a> From<&'a mut [u8]> for Ipv4Address<'a> {
    fn from(slice: &'a mut [u8]) -> Ipv4Address {
        Ipv4Address { ip: slice.try_into().unwrap() }
    }
}

impl<'a> Ipv4Address<'a> {
    pub fn get_address(&self) -> [u8; 4] {
        *self.ip
    }

    pub fn set_address(&mut self, new_address: &[u8; 4]) {
        self.ip.copy_from_slice(new_address);
    }
}

impl fmt::Debug for Ipv4Address<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{}.{}.{}.{}",
            self.ip[0], self.ip[1], self.ip[2], self.ip[3]
        ))
    }
}

#[derive(Debug)]
pub enum IpProtocol {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
    UNKNOWN,
}

#[derive(Debug)]
pub enum IpPayload<'a> {
    ICMP(IcmpPacket<'a>),
    Unknown(&'a mut [u8]),
    Uninitialized(&'a mut [u8]),
    None,
}

impl Default for IpPayload<'_> {
    fn default() -> Self {
        IpPayload::None
    }
}

pub struct Ipv4Packet<'a> {
    header: Ipv4Header<'a>,
    payload: IpPayload<'a>,
}

impl<'a> From <&'a mut [u8]> for Ipv4Packet<'a> {
    fn from(frame: &'a mut [u8]) -> Ipv4Packet {
        let ihl = frame[0] & 0x0F;

        let (header_bytes, payload_bytes) =
            frame.split_at_mut((ihl * 4) as usize);

        let header: Ipv4Header = header_bytes.into();

        Ipv4Packet {
            payload: match &header.protocol() {
                IpProtocol::ICMP => IpPayload::ICMP(payload_bytes.into()),
                _ => IpPayload::Unknown(payload_bytes),
            },
            header,
        }
    }
}

impl<'a> Ipv4Packet<'a> {
    pub fn new (
        buffer: &'a mut [u8],
        source_ip: &Ipv4Address,
        destination_ip: &Ipv4Address,
    ) -> Ipv4Packet<'a> {
        // Zero out the header
        for i in &mut buffer[0..20] { *i = 0; }

        let ihl: usize = 5;
        let (buf_header, buf_payload) = buffer.split_at_mut(4*ihl);

        let mut ipv4_packet = Ipv4Packet {
            header: buf_header.into(),
            payload: IpPayload::Uninitialized(buf_payload),
        };

        ipv4_packet.header().set_version(4);
        ipv4_packet.header().set_ihl(5);
        ipv4_packet.header().set_time_to_live(64);
        ipv4_packet.header().source_ip().set_address(&source_ip.get_address());
        ipv4_packet.header().destination_ip().set_address(&destination_ip.get_address());

        ipv4_packet
    }

    pub fn header(&mut self) -> &mut Ipv4Header<'a> {
        &mut self.header
    }

    pub fn payload(&mut self) -> &mut  IpPayload<'a> {
        &mut self.payload
    }

    pub fn take_payload_buffer(&mut self) -> &'a mut [u8] {
        let old_payload = take(&mut self.payload);
        if let IpPayload::Uninitialized(payload_bytes) = old_payload {
            payload_bytes
        } else {
            panic!("Unable to change existing ethertype");
        }
    }

    pub fn set_payload(&mut self, payload: IpPayload<'a>) {
        self.header.set_protocol(match payload {
            IpPayload::ICMP(_) => IpProtocol::ICMP as u8,
            _ => 0xFF,
        });

        self.payload = payload;
    }
}

impl<'a> std::fmt::Debug for Ipv4Packet<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let IpPayload::Unknown(bytes) =  &self.payload {
            f
                .debug_struct("Ipv4Packet")
                .field("header", &self.header)
                .field("payload", &format!("{} bytes", bytes.len()))
                .finish()
        } else {
            f
                .debug_struct("Ipv4Packet")
                .field("header", &self.header)
                .field("payload", &self.payload)
                .finish()
        }
    }
}

pub struct Ipv4Header<'a> {
    header: &'a mut [u8],
    source_ip: Ipv4Address<'a>,
    destination_ip:  Ipv4Address<'a>,
    options: Option<&'a mut [u8]>
}

impl<'a> From<&'a mut [u8]> for Ipv4Header<'a> {
    fn from(buffer: &'a mut [u8]) -> Self {
        let ihl = buffer[0] & 0x0F;

        let (header, rest) = buffer.split_at_mut(12);
        let (source_ip_bytes, rest) = rest.split_at_mut(4);
        let (destination_ip_bytes, rest) = rest.split_at_mut(4);
        let options;
        if ihl > 5 {
            let (options_bytes, rest) =
                rest.split_at_mut((ihl * 4 - 20) as usize);
            options = Some(options_bytes);
            assert_eq!(rest.len(), 0);
        } else {
            options = None;
            assert_eq!(rest.len(), 0);
        }

        Ipv4Header {
            header: header,
            source_ip: source_ip_bytes.into(),
            destination_ip: destination_ip_bytes.into(),
            options
        }
    }
}

impl<'a> Ipv4Header<'a> {
    pub fn source_ip(&mut self) -> &mut Ipv4Address<'a> {
        &mut self.source_ip
    }

    pub fn destination_ip(&mut self) -> &mut Ipv4Address<'a> {
        &mut self.destination_ip
    }

    pub fn version(&self) -> u8 {
        (self.header[0] & 0xF0) >> 4
    }

    pub fn set_version(&mut self, version: u8) {
        assert!(version <= 0x0F);
        let new_version_shifted = version << 4;
        let current = self.header[0];
        self.header[0] = (current & 0x0F) | new_version_shifted;
    }

    pub fn ihl(&self) -> u8 {
        self.header[0] & 0x0F
    }

    pub fn set_ihl(&mut self, ihl: u8) {
        assert!(ihl <= 0x0F);
        let current = self.header[0];
        self.header[0] = (current & 0xF0) | ihl;
    }

    pub fn dscp(&self) -> u8 {
        (self.header[1] & 0b11111100) >> 6
    }

    pub fn ecn(&self) -> u8 {
        self.header[1] & 0b00000011
    }

    pub fn length(&self) -> u16 {
        self.header[2..4].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    pub fn set_length(&mut self, length: u16) {
        self.header[2..4].as_mut().write_u16::<NetworkEndian>(length).unwrap();
    }

    pub fn identification(&self) -> u16 {
        self.header[4..6].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    pub fn flags(&self) -> u8 {
        (self.header[6] & 0b11100000) >> 5
    }

    pub fn fragment_offset(&self) -> u16 {
        self.header[6..8].as_ref().read_u16::<NetworkEndian>().unwrap() & 0x1FFF
    }

    pub fn time_to_live(&self) -> u8 {
        self.header[8]
    }

    pub fn set_time_to_live(&mut self, ttl: u8) {
        self.header[8] = ttl;
    }

    pub fn protocol(&self) -> IpProtocol {
        match self.header[9] {
            0x01 => IpProtocol::ICMP,
            0x06 => IpProtocol::TCP,
            0x11 => IpProtocol::UDP,
            _ => IpProtocol::UNKNOWN,
        }
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.header[9] = protocol;
    }

    pub fn checksum(&self) -> u16 {
        self.header[10..12].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    pub fn calculate_checksum(&mut self) {
        let mut checksum = Checksum::new();
        checksum.add_bytes(self.header);
        checksum.add_bytes(&self.source_ip.get_address());
        checksum.add_bytes(&self.destination_ip.get_address());
        self.header[10..12].copy_from_slice(&checksum.checksum());
        println!("IPv4 checksum set to: {:x}", self.checksum());
    }
}

impl<'a> std::fmt::Debug for Ipv4Header<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("Ipv4Header")
            .field("protocol", &self.protocol())
            .finish()
    }
}