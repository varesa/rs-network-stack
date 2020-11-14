use byteorder::{BigEndian, ReadBytesExt};
use crate::protocols::{HardwareAddress,ProtocolAddress};

#[derive(Debug)]
pub struct ArpPacket<'a> {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: ArpOperation,
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
        let (htype_bytes, rest) = frame.split_at_mut(2);
        // Support only ethernet
        assert_eq!(htype_bytes, [0x00, 0x01]);
        let (ptype_bytes, rest) = rest.split_at_mut(2);
        // Support only IPv4
        assert_eq!(ptype_bytes, [0x08, 0x00]);
        let (hlen_bytes, rest) = rest.split_at_mut(1);
        assert_eq!(hlen_bytes[0], 6); // MAC -> 6 octets
        let (plen_bytes, rest) = rest.split_at_mut(1);
        assert_eq!(plen_bytes[0], 4); // IPv4 -> 4 octets
        let (oper_bytes, rest) = rest.split_at_mut(2);
        let (sha_bytes, rest) = rest.split_at_mut(hlen_bytes[0] as usize);
        let (spa_bytes, rest) = rest.split_at_mut(plen_bytes[0] as usize);
        let (tha_bytes, rest) = rest.split_at_mut(hlen_bytes[0] as usize);
        let (tpa_bytes, rest) = rest.split_at_mut(plen_bytes[0] as usize);
        assert_eq!(rest.len(), 0);

        ArpPacket {
            htype: htype_bytes.as_ref().clone().read_u16::<BigEndian>().unwrap(),
            ptype: ptype_bytes.as_ref().clone().read_u16::<BigEndian>().unwrap(),
            hlen: hlen_bytes[0], plen: plen_bytes[0],
            oper: match oper_bytes {
                [0, 1] => ArpOperation::REQUEST,
                [0, 2] => ArpOperation::REPLY,
                _ => ArpOperation::INVALID,
            },
            sha: HardwareAddress::MAC(sha_bytes.into()),
            spa: ProtocolAddress::IPv4(spa_bytes.into()),
            tha: HardwareAddress::MAC(tha_bytes.into()),
            tpa: ProtocolAddress::IPv4(tpa_bytes.into()),
        }
    }
}

impl<'a> ArpPacket<'a> {
    pub fn oper(self: &Self) -> ArpOperation {
        self.oper
    }
    pub fn sha(self: &Self) -> &HardwareAddress {
        &self.sha
    }
    pub fn tha(self: &Self) -> &HardwareAddress {
        &self.tha
    }
    pub fn spa(self: &Self) -> &ProtocolAddress {
        &self.spa
    }
    pub fn tpa(self: &Self) -> &ProtocolAddress {
        &self.tpa
    }
}