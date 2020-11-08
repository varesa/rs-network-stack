use tun_tap::Iface;
use network_bridge::{interface_id,add_interface_to_bridge};
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
use netdevice::{set_flags, get_flags, IFF_UP};

use crate::error::Error;

fn set_if_up(interface: &Iface) -> Result<(), Error> {
    let socket = socket(AddressFamily::Unix, SockType::Stream, SockFlag::empty(), None)?;

    let mut flags = get_flags(socket, interface.name())?;
    flags = flags | IFF_UP;
    set_flags(socket, interface.name(), &flags)?;

    Ok(())

}

fn new_interface() -> Result<Iface, std::io::Error> {
    Iface::new("rs-test-if", tun_tap::Mode::Tap)
}

pub fn setup(bridge_name: &str) -> Iface {
    let iface = new_interface().unwrap();
    let iface_id = interface_id(iface.name()).unwrap();
    add_interface_to_bridge(iface_id, bridge_name).unwrap();
    set_if_up(&iface).unwrap();

    iface
}