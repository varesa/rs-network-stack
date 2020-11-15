//use heapless::FnvIndexMap;
//use heapless::consts::*;

use crate::protocols::*;
use crate::protocols::arp::*;
use crate::protocols::ethernet::{EthernetFrame, Payload};

//const MY_MAC_BYTES: &[u8] = &[];
//const MY_IP_BYTES: &[u8] = &[169, 254, 0, 2];

fn reply_arp<'a, F> (
    my_hardware_address: &HardwareAddress<'a>,
    my_protocol_address: &ProtocolAddress<'a>,
    arp_request: &mut ArpPacket<'a>,
    tx_buffer: &mut [u8],
    mut send: F
) -> ()
where
    F: FnMut(&[u8], usize) -> (),
{
    if &my_protocol_address == &arp_request.tpa() {
        println!("Hey, it's us!");

        let request_sha_bytes = &mut [0 as u8; 6];
        let request_spa_bytes = &mut [0 as u8; 4];

        {
            let HardwareAddress::MAC(sha) = arp_request.sha();
            request_sha_bytes.copy_from_slice(&sha.get_address());
        }
        {
            let ProtocolAddress::IPv4(spa) = arp_request.spa();
            request_spa_bytes.copy_from_slice(&spa.get_address());
        }

        /*
         * Ethernet header
         */
        let HardwareAddress::MAC(ref my_mac) = my_hardware_address;

        let mut arp_reply_eth_frame = EthernetFrame::uninitialized(tx_buffer);
        arp_reply_eth_frame.source_mac().set_address(&my_mac.get_address());
        arp_reply_eth_frame.destination_mac().set_address(&request_sha_bytes);

        /*
         * ARP header
         */

        let buf = arp_reply_eth_frame.take_payload_buffer();
        let arp_reply = ArpPacket::new(
            buf,
            ArpOperation::REPLY,
            &my_hardware_address,
            &my_protocol_address,
            &HardwareAddress::MAC(request_sha_bytes.as_mut().into()),
            &ProtocolAddress::IPv4(request_spa_bytes.as_mut().into()),
        );
        arp_reply_eth_frame.set_payload(Payload::ARP(arp_reply));

        if let Payload::ARP(ref mut arp_reply_payload) = arp_reply_eth_frame.payload() {
            arp_reply_payload.set_header_ethernet_ipv4();

        }

        println!("{:#x?}", arp_reply_eth_frame);
        send(&tx_buffer, 42);
    }
}

pub fn update<F>(rx_buffer: &mut [u8], tx_buffer: &mut [u8], mut send: F) -> ()
where
    F: FnMut(&[u8], usize) -> (),
{
    let my_mac_bytes: &mut [u8] = &mut [0x02, 0xDE, 0xAD, 0x00, 0xBE, 0xEF];
    let my_hardware_address = HardwareAddress::MAC(my_mac_bytes.into());
    let my_ip_bytes: &mut [u8] = &mut [169, 254, 0, 2];
    let my_protocol_address = ProtocolAddress::IPv4(my_ip_bytes.into());

    println!("Received {} bytes", rx_buffer.len());
    let mut frame = EthernetFrame::from_slice(rx_buffer);
    println!("{:#x?}", &frame);
    if let Payload::ARP(ref mut arp_request) = frame.payload() {
        if ArpOperation::REQUEST == arp_request.oper() {
            reply_arp(
                &my_hardware_address, &my_protocol_address,
                arp_request,
                tx_buffer,  send
            )
        }
    }
}