use byteorder::{BigEndian, ReadBytesExt};
use crate::protocols::{HardwareAddress,ProtocolAddress};
use std::fmt::Formatter;

pub struct ArpPacket<'a> {
    header: &'a mut [u8],
    sha: HardwareAddress<'a>,
    spa: ProtocolAddress<'a>,
    tha: HardwareAddress<'a>,
    tpa: ProtocolAddress<'a>,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ArpOperation {
    REQUEST,
    REPLY,
    INVALID,
}

impl<'a> From <&'a mut [u8]> for ArpPacket<'a> {
    fn from(frame: &'a mut [u8]) -> ArpPacket {

        let (header, rest) = frame.split_at_mut(8);

        let htype = header[0..2].as_ref().clone().read_u16::<BigEndian>().unwrap();
        let ptype = header[2..4].as_ref().clone().read_u16::<BigEndian>().unwrap();
        let hlen = header[4];
        let plen = header[5];

        // Support only ethernet
        assert_eq!(htype, 0x0001);
        assert_eq!(hlen, 6); // MAC -> 6 octets
        // Support only IPv4
        assert_eq!(ptype, 0x0800);
        assert_eq!(plen, 4); // IPv4 -> 4 octets

        let (sha_bytes, rest) = rest.split_at_mut(hlen as usize);
        let (spa_bytes, rest) = rest.split_at_mut(plen as usize);
        let (tha_bytes, rest) = rest.split_at_mut(hlen as usize);
        let (tpa_bytes, rest) = rest.split_at_mut(plen as usize);
        assert_eq!(rest.len(), 0);

        ArpPacket {
            header,
            sha: HardwareAddress::MAC(sha_bytes.into()),
            spa: ProtocolAddress::IPv4(spa_bytes.into()),
            tha: HardwareAddress::MAC(tha_bytes.into()),
            tpa: ProtocolAddress::IPv4(tpa_bytes.into()),
        }
    }
}


impl<'a> ArpPacket<'a> {
    pub fn new(
        buffer: &'a mut [u8],
        oper: ArpOperation,
        param_sha: &HardwareAddress,
        param_spa: &ProtocolAddress,
        param_tha: &HardwareAddress,
        param_tpa: &ProtocolAddress,

    ) -> ArpPacket<'a> {
        let (buffer, _excess) = buffer.split_at_mut(28);
        // Header: ethernet/ipv4
        let header = [0, 1, 8, 0, 6, 4];
        buffer[0..6].copy_from_slice(&header);

        let oper_bytes = match oper {
            ArpOperation::REQUEST => [0, 1],
            ArpOperation::REPLY => [0, 2],
            ArpOperation::INVALID => [0, 0],
        };
        buffer[6..8].copy_from_slice(&oper_bytes);

        let mut arp_packet: ArpPacket = buffer.into();

        let HardwareAddress::MAC(ref param_sha) = param_sha;
        let HardwareAddress::MAC(ref param_tha) = param_tha;
        let ProtocolAddress::IPv4(ref param_spa) = param_spa;
        let ProtocolAddress::IPv4(ref param_tpa) = param_tpa;

        let HardwareAddress::MAC(ref mut response_sha) = arp_packet.sha();
        response_sha.set_address(&param_sha.get_address());

        let ProtocolAddress::IPv4(ref mut response_spa) = arp_packet.spa();
        response_spa.set_address(&param_spa.get_address());

        let HardwareAddress::MAC(ref mut response_tha) = arp_packet.tha();
        response_tha.set_address(&param_tha.get_address());

        let ProtocolAddress::IPv4(ref mut response_tpa) = arp_packet.tpa();
        response_tpa.set_address(&param_tpa.get_address());

        arp_packet
    }

    pub fn set_header_ethernet_ipv4(&mut self) {
        // Htype
        self.header[0] = 0;
        self.header[1] = 1;
        // Ptype
        self.header[2] = 8;
        self.header[3] = 0;
        // Hlen
        self.header[4] = 6;
        // Plen
        self.header[5] = 4;
    }

    pub fn oper(&self) -> ArpOperation {
        match self.header[6..8] {
            [0, 1] => ArpOperation::REQUEST,
            [0, 2] => ArpOperation::REPLY,
            _ => ArpOperation::INVALID,
        }
    }

    pub fn set_oper(&mut self, oper: ArpOperation) {
        match oper {
            ArpOperation::REQUEST => { self.header[6] = 0; self.header[7] = 1; },
            ArpOperation::REPLY => { self.header[6] = 0; self.header[7] = 2; },
            ArpOperation::INVALID => { self.header[6] = 0; self.header[7] = 0; },
        }
    }

    pub fn sha(&mut self) -> &mut HardwareAddress<'a> {
        &mut self.sha
    }
    pub fn tha(&mut self) -> &mut HardwareAddress<'a> {
        &mut self.tha
    }
    pub fn spa(&mut self) -> &mut ProtocolAddress<'a> {
        &mut self.spa
    }
    pub fn tpa(&mut self) -> &mut ProtocolAddress<'a> {
        &mut self.tpa
    }

    pub fn fmt_header(&self) -> (String, String, String) {

        let hardware = match self.header[0..2] {
            [0x00, 0x01] => String::from("Ethernet"),
            _ => format!("Unknown hardware {:?}", &self.header[0..2]),
        };
        let protocol = match self.header[2..4] {
            [0x08, 0x00] => String::from("IPv4"),
            _ => format!("Unknown hardware {:?}", &self.header[2..4]),
        };

        (
            format!("{:?}", self.oper()),
            format!("{} ({} byte address)", hardware, self.header[4]),
            format!("{} ({} byte address)", protocol, self.header[5]),
        )
    }
}

impl<'a> std::fmt::Debug for ArpPacket<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArpPacket")
            .field("Header", &self.fmt_header())
            .field("Sender hardware address", &self.sha)
            .field("Sender protocol address", &self.spa)
            .field("Target hardware address", &self.tha)
            .field("Target protocol address", &self.tpa)
            .finish()
    }
}