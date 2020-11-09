use byteorder::{ReadBytesExt, BigEndian};
use heapless::FnvIndexMap;
use heapless::consts::*;
use std::convert::TryInto;
use std::fmt;

#[derive(Debug)]
struct ArpPacket<'a> {
    payload: &'a [u8],
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
}

struct MacAddress<'a> {
    mac: &'a [u8; 6],
}

impl MacAddress<'_> {
    fn from_slice(mac: &[u8]) -> MacAddress {
        MacAddress {
            mac: mac.try_into().unwrap(),
        }
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
            source_mac: MacAddress::from_slice(source_mac_bytes),
            destination_mac: MacAddress::from_slice(destination_mac_bytes),
            payload: match ethertype {
                0x0800 => EtherType::IPv4,
                0x0806 => EtherType::ARP(ArpPacket { payload }),
                0x86DD => EtherType::IPv6,
                _ => EtherType::Unknown(UnknownEtherTypePayload { ethertype, payload }),
            },
        }
    }
}

pub fn update(frame: &[u8]) -> () {
    println!("Received {} bytes", frame.len());
    let frame = EthernetFrame::from_slice(frame);
    println!("{:#x?}", frame);
}