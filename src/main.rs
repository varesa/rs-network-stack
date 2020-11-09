mod error;
mod tap;
mod net;

use std::{env};

struct Args {
    bridge_name: String,
}

fn parse_args() -> Args {
    let mut args = env::args().collect::<Vec<String>>();

    if args.len() != 2 {
        panic!(format!("Usage: {} <bridge name>", args.get(0).unwrap()));
    }

    let bridge_name = args.remove(1);

    Args {
        bridge_name
    }
}

fn main() {

    let args = parse_args();

    println!("Using bridge {}", &args.bridge_name);

    let iface = tap::setup(&args.bridge_name);

    const MTU: usize = 1500;
    const TAP_HEADER: usize = 4;

    let mut buffer = [0 as u8; MTU + TAP_HEADER];

    loop { 
        //thread::sleep(time::Duration::from_millis(100));
        let size = iface.recv(&mut buffer).unwrap();
        net::update(&buffer[TAP_HEADER .. TAP_HEADER+size]);
    }
}
