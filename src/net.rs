//use heapless::FnvIndexMap;
//use heapless::consts::*;

use crate::protocols::*;
use crate::protocols::arp::*;
use crate::protocols::ethernet::{EthernetFrame, Payload};
use crate::protocols::ipv4::{IpPayload, Ipv4Packet};
use crate::protocols::icmp::{IcmpType, IcmpPacket};

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

        println!("{:#x?}", arp_reply_eth_frame);
        send(&tx_buffer, 42);
    }
}

fn reply_ping<'a, F> (
    my_hardware_address: &HardwareAddress<'a>,
    my_protocol_address: &ProtocolAddress<'a>,
    echo_request: &mut IcmpPacket<'a>,
    tx_buffer: &mut [u8],
    mut send: F
) -> ()
    where
        F: FnMut(&[u8], usize) -> (),
{
    let mut arp_reply_eth_frame = EthernetFrame::uninitialized(tx_buffer);

    let HardwareAddress::MAC(ref my_mac) = my_hardware_address;
    arp_reply_eth_frame.source_mac().set_address(&my_mac.get_address());
    arp_reply_eth_frame.destination_mac().set_address(&[0x72, 0x59, 0x69, 0x20, 0x9a, 0xaf]);
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
    match frame.payload() {
        Payload::ARP(ref mut arp_request)  => {
            if ArpOperation::REQUEST == arp_request.oper() {
                reply_arp(
                    &my_hardware_address, &my_protocol_address,
                    arp_request,
                    tx_buffer,  send
                )
            }
        },
        Payload::IPv4(ref mut ipv4_packet) => {
            let ProtocolAddress::IPv4(my_ipv4_addresss) = my_protocol_address;
            if ipv4_packet.header().destination_ip() == &my_ipv4_addresss {
                let response_source_address_bytes = &mut [0 as u8; 4];
                let response_destination_address_bytes = &mut [0 as u8; 4];
                response_source_address_bytes.copy_from_slice(&ipv4_packet.header().destination_ip().get_address());
                response_destination_address_bytes.copy_from_slice(&ipv4_packet.header().source_ip().get_address());

                match ipv4_packet.payload() {
                    IpPayload::ICMP(icmp_packet)  => {
                        match icmp_packet.icmp_type() {
                            IcmpType::EchoRequest => {
                                //let mut icmp_seq_id = [0u8; 4];
                                //icmp_seq_id.copy_from_slice(icmp_packet.rest_of_header());

                                println!("Pong..?");


                                let mut reply_ethernet_frame = EthernetFrame::uninitialized(tx_buffer);
                                let ethernet_payload_buffer = reply_ethernet_frame.take_payload_buffer();
                                let mut ipv4_packet = Ipv4Packet::new(
                                    ethernet_payload_buffer,
                                    &response_source_address_bytes.as_mut().into(),
                                    &response_destination_address_bytes.as_mut().into(),
                                );

                                let ip_payload_buffer = ipv4_packet.take_payload_buffer();
                                let mut icmp_response_packet = IcmpPacket::new(
                                    ip_payload_buffer,
                                );

                                icmp_response_packet.set_rest_of_header(&icmp_packet.rest_of_header());
                                icmp_response_packet.data[0..56].copy_from_slice(icmp_packet.data);
                                icmp_response_packet.calculate_checksum();

                                ipv4_packet.set_payload(IpPayload::ICMP(icmp_response_packet));
                                ipv4_packet.header().set_length(84);
                                ipv4_packet.header().calculate_checksum();
                                reply_ethernet_frame.set_payload(Payload::IPv4(ipv4_packet));
                                println!("{:#x?}", reply_ethernet_frame);
                                send(&tx_buffer, 98);
                            }
                            _  => {}
                        }
                    }
                    _ => {}
                }
            }

        }
        _ => {}
    }
}