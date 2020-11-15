use std::convert::TryInto;
use std::fmt;
use byteorder::{NetworkEndian, ReadBytesExt};
use std::fmt::{Formatter, Debug};
use crate::protocols::icmp::IcmpPacket;

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
enum IpProtocol {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
    UNKNOWN,
}

#[derive(Debug)]
enum IpPayload<'a> {
    ICMP(IcmpPacket<'a>),
    Unknown(&'a mut [u8])
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

struct Ipv4Header<'a> {
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
    fn version(&self) -> u8 {
        (self.header[0] & 0xF0) >> 4
    }

    fn ihl(&self) -> u8 {
        self.header[0] & 0x0F
    }

    fn dscp(&self) -> u8 {
        (self.header[1] & 0b11111100) >> 6
    }

    fn ecn(&self) -> u8 {
        self.header[1] & 0b00000011
    }

    fn length(&self) -> u16 {
        self.header[2..4].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    fn identification(&self) -> u16 {
        self.header[4..6].as_ref().read_u16::<NetworkEndian>().unwrap()
    }

    fn flags(&self) -> u8 {
        (self.header[6] & 0b11100000) >> 5
    }

    fn fragment_offset(&self) -> u16 {
        self.header[6..8].as_ref().read_u16::<NetworkEndian>().unwrap() & 0x1FFF
    }

    fn time_to_live(&self) -> u8 {
        self.header[8]
    }

    fn protocol(&self) -> IpProtocol {
        match self.header[9] {
            0x01 => IpProtocol::ICMP,
            0x06 => IpProtocol::TCP,
            0x11 => IpProtocol::UDP,
            _ => IpProtocol::UNKNOWN,
        }
    }

    fn checksum(&self) -> u16 {
        self.header[10..12].as_ref().read_u16::<NetworkEndian>().unwrap()
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