use pcap_file::pcap::Packet;
use pcap_file::PcapReader;
use lib_lime::packet::{is_beacon, is_probe, get_packet_channel};

use lib_lime::api::grpc_server;
use lib_lime::cache;

#[tokio::main]
async fn main() {
    tokio::spawn(async {
        println!("Starting gRPC server");
        grpc_server::run_grpc_server().await.unwrap();
    });

    cache::add_bssid("Outlook Guest".to_string());
    cache::add_probe("Outlook Home".to_string());

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

        let was_cached = false;

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

