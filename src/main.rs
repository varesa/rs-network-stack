use std::{env,thread,time};
use std::result::Result;
//use std::error::Error;
use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
//use std::ffi::CString;
use netdevice::{set_flags, get_flags, IFF_UP};

use tun_tap::Iface;
use network_bridge::{interface_id,add_interface_to_bridge};

#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
    NixError(nix::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::NixError(err)
    }
}


fn set_if_up(interface: &Iface) -> Result<(), Error> {
    let socket = socket(AddressFamily::Unix, SockType::Stream, SockFlag::empty(), None)?;

    let mut flags = get_flags(socket, interface.name())?;
    flags = flags | IFF_UP;
    set_flags(socket, interface.name(), &flags)?;

    Ok(())

}

fn create_iface() -> Result<Iface, std::io::Error> {
    Iface::new("rs-test-if", tun_tap::Mode::Tap)
}

fn main() {
    let args = env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        panic!(format!("Usage: {} <bridge name>", args.get(0).unwrap()));
    }

    let bridge_name = args.get(1).unwrap();
    println!("Using bridge {}", bridge_name);

    let iface = create_iface().unwrap();
    let iface_id = interface_id(iface.name()).unwrap();
    add_interface_to_bridge(iface_id, bridge_name).unwrap();
    set_if_up(&iface).unwrap();


    let mut buffer = vec![0; 1500];

    loop { 
        //thread::sleep(time::Duration::from_millis(100));
        let data = iface.recv(&mut buffer).unwrap();
        println!("{:#}", data);
    }
}
