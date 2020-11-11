use std::convert::TryInto;
use std::fmt;

// Custom fmt::Debug
#[derive(PartialEq)]
pub struct Ipv4Address<'a> {
    ip: &'a [u8; 4],
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

