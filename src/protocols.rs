pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod icmp;

use ipv4::Ipv4Address;
use ethernet::MacAddress;

#[derive(Debug)]
pub enum HardwareAddress<'a> {
    MAC(MacAddress<'a>),
}

#[derive(Debug, PartialEq)]
pub enum ProtocolAddress<'a> {
    IPv4(Ipv4Address<'a>),
}