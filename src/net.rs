//use heapless::FnvIndexMap;
//use heapless::consts::*;

use crate::protocols::*;
use crate::protocols::arp::*;
use crate::protocols::ethernet::{EthernetFrame, Payload};

//const MY_MAC_BYTES: &[u8] = &[];
//const MY_IP_BYTES: &[u8] = &[169, 254, 0, 2];

pub fn update<F>(rx_buffer: &mut [u8], tx_buffer: &mut [u8], send: F) -> ()
where
    F: FnMut(&[u8], usize) -> (),
{
    let my_mac_bytes: &mut [u8] = &mut [0x02, 0xDE, 0xAD, 0x00, 0xBE, 0xEF];
    let my_ip_bytes: &mut [u8] = &mut [169, 254, 0, 2];

    println!("Received {} bytes", rx_buffer.len());
    let frame = EthernetFrame::from_slice(rx_buffer);
    println!("{:#x?}", &frame);
    if let Payload::ARP(arp_request) = &frame.payload() {
        if ArpOperation::REQUEST == arp_request.oper() {
            if &ProtocolAddress::IPv4(my_ip_bytes.into()) == arp_request.tpa() {
                println!("Hey, it's us!");

                let mut arp_reply = EthernetFrame::uninitialized(tx_buffer);
                let HardwareAddress::MAC(sha) = arp_request.sha();
                let HardwareAddress::MAC(tha) = arp_request.tha();

                arp_reply.destination_mac().set_address(&sha.get_address());
                arp_reply.source_mac().set_address(&tha.get_address());

                println!("{:?}", arp_reply.destination_mac());
            }
        }
    }
}