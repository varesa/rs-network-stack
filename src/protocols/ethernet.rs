use byteorder::{NetworkEndian, ReadBytesExt};
use std::convert::TryInto;
use std::fmt;
use std::mem::take;
use crate::protocols::arp::*;

// Ethernet frame

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    source_mac: MacAddress<'a>,
    destination_mac: MacAddress<'a>,
    payload: Payload<'a>,
}

impl<'a> EthernetFrame<'a> {

    fn generate_payload(ethertype: u16, bytes: &mut [u8]) -> Payload{
        match ethertype {
            0x0800 => Payload::IPv4,
            0x0806 => Payload::ARP(bytes.into()),
            0x86DD => Payload::IPv6,
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
            payload: EthernetFrame::generate_payload(ethertype, payload_bytes),
        }
    }

    pub fn uninitialized(frame: &mut [u8]) -> EthernetFrame {
        let [
        destination_mac_bytes,
        source_mac_bytes,
        _ethertype_bytes,
        payload_bytes
        ] = EthernetFrame::split_buffer(frame);

        EthernetFrame {
            source_mac: source_mac_bytes.into(),
            destination_mac: destination_mac_bytes.into(),
            payload: Payload::Uninitialized(payload_bytes),
        }
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
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
        } else {
            panic!("Unable to change existing ethertype");
        }
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