use byteorder::{ReadBytesExt, BigEndian};
//use heapless::FnvIndexMap;
//use heapless::consts::*;
use std::convert::{TryFrom,TryInto};
use std::fmt;

use crate::protocols::arp::*;

const MY_MAC_BYTES: &[u8] = &[0x02, 0xDE, 0xAD, 0x00, 0xBE, 0xEF];
const MY_IP_BYTES: &[u8] = &[169, 254, 0, 2];

#[derive(Debug)]
pub enum HardwareAddress<'a> {
    MAC(MacAddress<'a>),
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum ProtocolAddress<'a> {
    IPv4(Ipv4Address<'a>),
}



#[derive(Debug)]
struct UnknownEtherTypePayload<'a> {
    ethertype: u16,
    payload: &'a [u8],
}

#[derive(Debug)]
enum EtherType<'a> {
    ARP(ArpPacket<'a>),
    IPv4,
    IPv6,
    Unknown(UnknownEtherTypePayload<'a>),
    Uninitialized(&'a [u8]),
}

// Custom fmt::Debug
#[derive(PartialEq)]
pub struct MacAddress<'a> {
    mac: &'a [u8; 6],
}

// Custom fmt::Debug
#[derive(PartialEq)]
pub struct Ipv4Address<'a> {
    ip: &'a [u8; 4],
}

impl<'a> From<&'a [u8]> for MacAddress<'a> {
    fn from(slice: &'a [u8]) -> MacAddress {
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

impl<'a> From<&'a [u8]> for Ipv4Address<'a> {
    fn from(slice: &'a [u8]) -> Ipv4Address {
        Ipv4Address { ip: slice.try_into().unwrap() }
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
struct EthernetFrame<'a> {
    source_mac: MacAddress<'a>,
    destination_mac: MacAddress<'a>,
    payload: EtherType<'a>,
}

fn ethertype_slice_to_u16 (ethertype: &[u8]) -> u16 {
    ethertype.clone().read_u16::<BigEndian>().unwrap()
}

impl EthernetFrame<'_> {
    fn from_slice(frame: &[u8]) -> EthernetFrame {
        let (destination_mac_bytes, rest) = frame.split_at(6);
        let (source_mac_bytes, rest) = rest.split_at(6);
        let (ethertype_bytes, payload) = rest.split_at(2);

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
}

pub fn update<F>(rx_buffer: &[u8], tx_buffer: &mut [u8], send: F) -> ()
where
    F: FnMut(&[u8], usize) -> (),
{
    println!("Received {} bytes", rx_buffer.len());
    let frame = EthernetFrame::from_slice(rx_buffer);
    println!("{:#x?}", &frame);
    if let EtherType::ARP(arp_packet) = &frame.payload {
        if ArpOperation::REQUEST == arp_packet.oper() {
            if &ProtocolAddress::IPv4(MY_IP_BYTES.into()) == arp_packet.tpa() {
                println!("Hey, it's us!");
            }
        }
    }
}