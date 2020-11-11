//use heapless::FnvIndexMap;
//use heapless::consts::*;

use crate::protocols::*;
use crate::protocols::arp::*;
use crate::protocols::ethernet::{EthernetFrame, EtherType};

const MY_MAC_BYTES: &[u8] = &[0x02, 0xDE, 0xAD, 0x00, 0xBE, 0xEF];
const MY_IP_BYTES: &[u8] = &[169, 254, 0, 2];

pub fn update<F>(rx_buffer: &[u8], tx_buffer: &mut [u8], send: F) -> ()
where
    F: FnMut(&[u8], usize) -> (),
{
    println!("Received {} bytes", rx_buffer.len());
    let frame = EthernetFrame::from_slice(rx_buffer);
    println!("{:#x?}", &frame);
    if let EtherType::ARP(arp_packet) = &frame.payload() {
        if ArpOperation::REQUEST == arp_packet.oper() {
            if &ProtocolAddress::IPv4(MY_IP_BYTES.into()) == arp_packet.tpa() {
                println!("Hey, it's us!");
            }
        }
    }
}