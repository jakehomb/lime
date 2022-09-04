use pcap_file::pcap::Packet;
use pcap_file::PcapReader;
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::collections::HashMap;
use lib_lime::packet::{is_beacon, is_probe, get_packet_channel};

lazy_static! {
    static ref DISCOVERED: Mutex<HashMap<String, lib_lime::bssid_information::BSSID>> = Mutex::new(HashMap::new());
}

fn main() {
    let mut input = std::io::stdin();

    PcapReader::new(&mut input).unwrap().for_each(|packet| {
        match packet {
            Ok(packet) => {
                handle_packet(&packet);                
            }
            Err(e) => {
                println!("error: {:?}", e);
            }
        }
    });
}



fn handle_packet(packet: &Packet) {
    if is_beacon(packet) {
        let bssid = match lib_lime::packet::parser::parse_ssid_from_beacon(packet) {
            Ok(bssid) => bssid,
            Err(_) => {
                // println!("error: {:?}", e);
                return;
            }
        };
    
        let bssid_clone = bssid.clone();

        let was_cached = cache_ssid(bssid);

        if !was_cached {
            println!("Beacon for SSID: {}", bssid_clone.to_string());
            println!("SSID Broadcast on channel: {}", get_packet_channel(packet));
        }
        
    }

    if is_probe(packet) {
        let bssid = match lib_lime::packet::parser::parse_ssid_from_probe(packet) {
            Ok(bssid) => bssid,
            Err(_e) => {
                // println!("error: {:?}", _e);
                return;
            }
        };
        println!("Probe request for SSID: {}", bssid);
        println!("Probe on channel: {}", get_packet_channel(packet));
    }
}

fn cache_ssid(ssid: String) -> bool{
    let mut discovered = DISCOVERED.lock().unwrap();
    if !discovered.contains_key(&ssid) {
        let ssid_copy = ssid.clone();
        let bssid = lib_lime::bssid_information::BSSID::new(ssid);
        let ssid = bssid.get_ssid().clone().to_string();
        discovered.insert(ssid, bssid);
        
        println!("Discovered SSID: {}", ssid_copy);
        return false;
    } 
    return true;
}