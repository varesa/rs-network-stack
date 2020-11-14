use std::convert::TryInto;
use std::fmt;

// Custom fmt::Debug
#[derive(PartialEq)]
pub struct Ipv4Address<'a> {
    ip: &'a mut [u8; 4],
}

impl<'a> From<&'a mut [u8]> for Ipv4Address<'a> {
    fn from(slice: &'a mut [u8]) -> Ipv4Address {
        Ipv4Address { ip: slice.try_into().unwrap() }
    }
}

impl<'a> Ipv4Address<'a> {
    pub fn get_address(&self) -> [u8; 4] {
        *self.ip
    }

    pub fn set_address(&mut self, new_address: &[u8; 4]) {
        self.ip.copy_from_slice(new_address);
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

