//use heapless::FnvIndexMap;
//use heapless::consts::*;

use crate::protocols::*;
use crate::protocols::arp::*;
use crate::protocols::ethernet::{EthernetFrame, Payload, EtherType};

//const MY_MAC_BYTES: &[u8] = &[];
//const MY_IP_BYTES: &[u8] = &[169, 254, 0, 2];

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
            if &my_protocol_address == arp_request.tpa() {
                println!("Hey, it's us!");

                /*
                 * Ethernet header
                 */

                let mut arp_reply = EthernetFrame::uninitialized(tx_buffer);
                {
                    let HardwareAddress::MAC(sha) = arp_request.sha();
                    arp_reply.destination_mac().set_address(&sha.get_address());
                }
                {
                    let HardwareAddress::MAC(tha) = arp_request.tha();
                    let HardwareAddress::MAC(ref my_mac) = my_hardware_address;
                    arp_reply.source_mac().set_address(&my_mac.get_address());
                }
                arp_reply.set_ethertype(EtherType::ARP.into());

                /*
                 * ARP header
                 */

                if let Payload::ARP(ref mut arp_reply_payload) = arp_reply.payload() {
                    arp_reply_payload.set_header_ethernet_ipv4();
                    arp_reply_payload.set_oper(ArpOperation::REPLY);

                    // Response source host address -> Self
                    {
                        let HardwareAddress::MAC(ref mut response_sha) = arp_reply_payload.sha();
                        let HardwareAddress::MAC(ref my_mac_address) = my_hardware_address;
                        response_sha.set_address(&my_mac_address.get_address());
                    }

                    // Response source protocol address -> Self
                    {
                        let ProtocolAddress::IPv4(ref mut response_spa) = arp_reply_payload.spa();
                        let ProtocolAddress::IPv4(ref my_ipv4_address) = my_protocol_address;
                        response_spa.set_address(&my_ipv4_address.get_address());
                    }

                    // Response target host address -> request source host address
                    {
                        let HardwareAddress::MAC(ref mut response_tha) = arp_reply_payload.tha();
                        let HardwareAddress::MAC(ref mut query_sha) = arp_request.sha();
                        response_tha.set_address(&query_sha.get_address());
                    }

                    // Response target protocol address -> request source protocol address
                    {
                        let ProtocolAddress::IPv4(ref mut response_tpa) = arp_reply_payload.tpa();
                        let ProtocolAddress::IPv4(ref query_spa) = arp_request.spa();
                        response_tpa.set_address(&query_spa.get_address());
                    };
                }

                println!("{:#x?}", arp_reply);
                send(&tx_buffer, 42);
            }
        }
    }
}