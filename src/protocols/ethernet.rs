use byteorder::{BigEndian, ReadBytesExt};
use std::convert::TryInto;
use std::fmt;
use crate::protocols::arp::*;

// Ethernet frame

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    source_mac: MacAddress<'a>,
    destination_mac: MacAddress<'a>,
    payload: EtherType<'a>,
}

impl EthernetFrame<'_> {
    pub fn from_slice(frame: &mut [u8]) -> EthernetFrame {
        let (destination_mac_bytes, rest) = frame.split_at_mut(6);
        let (source_mac_bytes, rest) = rest.split_at_mut(6);
        let (ethertype_bytes, payload) = rest.split_at_mut(2);

        let ethertype = ethertype_slice_to_u16(ethertype_bytes);

        EthernetFrame {
            source_mac: source_mac_bytes.into(),
            destination_mac: destination_mac_bytes.into(),
            payload: match ethertype {
                0x0800 => EtherType::IPv4,
                0x0806 => EtherType::ARP(payload.into()),
                0x86DD => EtherType::IPv6,
                _ => EtherType::Unknown(UnknownEtherTypePayload { ethertype, payload }),
            },
        }
    }

    pub fn payload(self: &Self) -> &EtherType {
        &self.payload
    }
}

fn ethertype_slice_to_u16 (ethertype: &[u8]) -> u16 {
    ethertype.clone().read_u16::<BigEndian>().unwrap()
}

#[derive(Debug)]
pub enum EtherType<'a> {
    ARP(ArpPacket<'a>),
    IPv4,
    IPv6,
    Unknown(UnknownEtherTypePayload<'a>),
    Uninitialized(&'a mut [u8]),
}

#[derive(Debug)]
pub struct UnknownEtherTypePayload<'a> {
    ethertype: u16,
    payload: &'a mut [u8],
}

// MAC address

#[derive(PartialEq)]
pub struct MacAddress<'a> {
    mac: &'a mut [u8; 6],
}

impl<'a> From<&'a mut [u8]> for MacAddress<'a> {
    fn from(slice: &'a mut [u8]) -> MacAddress {
        MacAddress { mac: slice.try_into().unwrap() }
    }
}

impl fmt::Debug for MacAddress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5]
        ))
    }
}