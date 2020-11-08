mod error;
mod tap;

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
    let mut buffer = [0 as u8; 1500];

    loop { 
        //thread::sleep(time::Duration::from_millis(100));
        let size = iface.recv(&mut buffer).unwrap();
        println!("Received {} bytes", size);
    }
}
