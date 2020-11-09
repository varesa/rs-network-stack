use byteorder::{ReadBytesExt, BigEndian};
use heapless::FnvIndexMap;
use heapless::consts::*;
use std::io::BufRead;
use std::convert::TryInto;
use std::fmt;

//const OFFSET_DESTINATION_MAC: usize = 0;
//const OFFSET_SOURCE_MAC: usize = 6;
const OFFSET_ETHERTYPE: usize = 12;
const OFFSET_PAYLOAD: usize = 14;

#[derive(Debug)]
enum EtherType {
    ARP,
    IPv4,
    IPv6,
    Unknown(u16),
}

fn get_ethertype(ethertype: &[u8]) -> EtherType {
    //println!("{:x?}", &frame[0 .. 17]);
    //let ethertype = &frame[OFFSET_ETHERTYPE .. OFFSET_PAYLOAD];
    //println!("{:#?}", fields);
    match ethertype {
        [0x08, 0x00] => EtherType::IPv4,
        [0x08, 0x06] => EtherType::ARP,
        [0x86, 0xDD] => EtherType::IPv6,
        _ => EtherType::Unknown(ethertype.clone().read_u16::<BigEndian>().unwrap()),
    }
}


#[derive(Debug)]
struct EthernetFrame<'a> {
    source_mac: &'a [u8; 6],
    destination_mac: &'a [u8; 6],
    ethertype: EtherType,
}

impl EthernetFrame<'_> {
    fn from_slice(frame: &[u8]) -> EthernetFrame {
        let (destination_mac, rest) = frame.split_at(6);
        let (source_mac, rest) = rest.split_at(6);
        let (ethertype, payload) = rest.split_at(2);

        EthernetFrame {
            source_mac: source_mac.try_into().unwrap(),
            destination_mac: destination_mac.try_into().unwrap(),
            ethertype: get_ethertype(ethertype),
        }
    }
}

pub fn update(frame: &[u8]) -> () {
    println!("Received {} bytes", frame.len());
    //let ethertype = get_ethertype(&frame);
    //println!("Type: {:x?}", ethertype);
    let frame = EthernetFrame::from_slice(frame);
    println!("{:#x?}", frame);
}