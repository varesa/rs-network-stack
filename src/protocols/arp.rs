use byteorder::{BigEndian, ReadBytesExt};
use crate::protocols::{HardwareAddress,ProtocolAddress};

#[derive(Debug)]
pub struct ArpPacket<'a> {
    header: &'a mut [u8],
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
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

        let (sha_bytes, rest) = rest.split_at_mut(6);
        let (spa_bytes, rest) = rest.split_at_mut(4);
        let (tha_bytes, rest) = rest.split_at_mut(6);
        let (tpa_bytes, rest) = rest.split_at_mut(4);
        //assert_eq!(rest.len(), 0);

        ArpPacket {
            header,
            htype,
            ptype,
            hlen,
            plen,
            sha: HardwareAddress::MAC(sha_bytes.into()),
            spa: ProtocolAddress::IPv4(spa_bytes.into()),
            tha: HardwareAddress::MAC(tha_bytes.into()),
            tpa: ProtocolAddress::IPv4(tpa_bytes.into()),
        }
    }
}

impl<'a> ArpPacket<'a> {
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
}