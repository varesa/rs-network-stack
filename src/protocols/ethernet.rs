use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryInto;
use std::fmt;
use std::mem::take;
use crate::protocols::arp::*;

// Ethernet frame

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    source_mac: MacAddress<'a>,
    destination_mac: MacAddress<'a>,
    ethertype_bytes: &'a mut [u8],
    payload: Payload<'a>,
}

impl<'a> EthernetFrame<'a> {

    fn generate_payload(ethertype: u16, bytes: &mut [u8]) -> Payload{
        match EtherType::from_u16(ethertype) {
            EtherType::IPv4 => Payload::IPv4,
            EtherType::ARP => Payload::ARP(bytes.into()),
            EtherType::IPv6 => Payload::IPv6,
            _ => Payload::Unknown(UnknownPayload { ethertype, bytes }),
        }
    }

    fn split_buffer(frame: &mut [u8]) -> [&mut[u8]; 4] {
        let (destination_mac_bytes, rest) = frame.split_at_mut(6);
        let (source_mac_bytes, rest) = rest.split_at_mut(6);
        let (ethertype_bytes, payload_bytes) = rest.split_at_mut(2);

        [destination_mac_bytes, source_mac_bytes, ethertype_bytes, payload_bytes]
    }

    pub fn from_slice(frame: &mut [u8]) -> EthernetFrame {
        let [
            destination_mac_bytes,
            source_mac_bytes,
            ethertype_bytes,
            payload_bytes
        ] = EthernetFrame::split_buffer(frame);

        let ethertype = ethertype_slice_to_u16(ethertype_bytes);

        EthernetFrame {
            source_mac: source_mac_bytes.into(),
            destination_mac: destination_mac_bytes.into(),
            ethertype_bytes,
            payload: EthernetFrame::generate_payload(ethertype, payload_bytes),
        }
    }

    pub fn uninitialized(frame: &mut [u8]) -> EthernetFrame {
        let [
        destination_mac_bytes,
        source_mac_bytes,
        ethertype_bytes,
        payload_bytes
        ] = EthernetFrame::split_buffer(frame);

        EthernetFrame {
            source_mac: source_mac_bytes.into(),
            destination_mac: destination_mac_bytes.into(),
            ethertype_bytes,
            payload: Payload::Uninitialized(payload_bytes),
        }
    }

    pub fn payload(&mut self) -> &mut Payload<'a> {
        &mut self.payload
    }

    pub fn source_mac(&mut self) -> &mut MacAddress<'a> {
        &mut self.source_mac
    }

    pub fn destination_mac(&mut self) -> &mut MacAddress<'a> {
        &mut self.destination_mac
    }

    pub fn set_ethertype(&mut self, ethertype: u16) {
        let old_payload = take(&mut self.payload);
        if let Payload::Uninitialized(payload_bytes) = old_payload {
            self.payload = EthernetFrame::generate_payload(ethertype, payload_bytes);
            self.ethertype_bytes.write_u16::<NetworkEndian>(ethertype);
        } else {
            panic!("Unable to change existing ethertype");
        }
    }
}

pub enum EtherType {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    Unknown,
}

impl EtherType {
    fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::IPv6,
            _      => EtherType::Unknown,
        }
    }
}

impl Into<u16> for EtherType {
    fn into(self) -> u16 {
        self as u16
    }
}

fn ethertype_slice_to_u16 (ethertype: &[u8]) -> u16 {
    ethertype.clone().read_u16::<NetworkEndian>().unwrap()
}

#[derive(Debug)]
pub enum Payload<'a> {
    ARP(ArpPacket<'a>),
    IPv4,
    IPv6,
    Unknown(UnknownPayload<'a>),
    Uninitialized(&'a mut [u8]),
    None,
}

impl Default for Payload<'_> {
    fn default() -> Self {
        Payload::None
    }
}


#[derive(Debug)]
pub struct UnknownPayload<'a> {
    ethertype: u16,
    bytes: &'a mut [u8],
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

impl<'a> MacAddress<'a> {
    pub fn get_address(&self) -> [u8; 6] {
        *self.mac
    }

    pub fn set_address(&mut self, new_address: &[u8; 6]) {
        self.mac.copy_from_slice(new_address);
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