use byteorder::{ReadBytesExt, BigEndian};

//const OFFSET_DESTINATION_MAC: usize = 0;
//const OFFSET_SOURCE_MAC: usize = 6;
const OFFSET_ETHERTYPE: usize = 12;
const OFFSET_PAYLOAD: usize = 14;

#[derive(Debug)]
enum EtherType {
    ARP,
    IPv4,
    IPv6,
    Unknown(u16),
}

fn get_ethertype(frame: &[u8]) -> EtherType {
    //println!("{:x?}", &frame[0 .. 17]);
    let ethertype = &frame[OFFSET_ETHERTYPE .. OFFSET_PAYLOAD];
    //println!("{:#?}", fields);
    match ethertype {
        [0x08, 0x00] => EtherType::IPv4,
        [0x08, 0x06] => EtherType::ARP,
        [0x86, 0xDD] => EtherType::IPv6,
        _ => EtherType::Unknown(ethertype.clone().read_u16::<BigEndian>().unwrap()),
    }
}

pub fn update(frame: &[u8]) -> () {
    println!("Received {} bytes", frame.len());
    let ethertype = get_ethertype(&frame);
    println!("Type: {:x?}", ethertype);
}