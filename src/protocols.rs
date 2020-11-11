pub mod arp;
pub mod ethernet;
pub mod ipv4;

use ipv4::Ipv4Address;
use ethernet::MacAddress;

#[derive(Debug)]
pub enum HardwareAddress<'a> {
    MAC(MacAddress<'a>),
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum ProtocolAddress<'a> {
    IPv4(Ipv4Address<'a>),
}