use pcap_file::pcap::Packet;
use pcap_file::PcapReader;
use radiotap::field::Channel;
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::collections::HashMap;
mod broadcast_info;

lazy_static! {
    static ref DISCOVERED: Mutex<HashMap<String, broadcast_info::BSSID>> = Mutex::new(HashMap::new());
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

fn is_beacon(packet: &Packet) -> bool {
    let frame_ctrl = packet.data[16];

    return frame_ctrl == 0x80;
}

fn is_probe(packet: &Packet) -> bool {
    let frame_ctrl = packet.data[16];

    return frame_ctrl == 0x40;
}

fn handle_packet(packet: &Packet) {
    if is_beacon(packet) {
        let bssid = match parse_ssid_tag(packet) {
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
        let bssid = match parse_ssid_from_probe(packet) {
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

const TAG_PARAM_OFFSET : usize = 52;

fn cache_ssid(ssid: String) -> bool{
    let mut discovered = DISCOVERED.lock().unwrap();
    if !discovered.contains_key(&ssid) {
        let ssid_copy = ssid.clone();
        let bssid = broadcast_info::BSSID::new(ssid);
        let ssid = bssid.get_ssid().clone().to_string();
        discovered.insert(ssid, bssid);
        
        println!("Discovered SSID: {}", ssid_copy);
        return false;
    } 
    return true;
}

fn parse_ssid_tag(packet: &Packet) -> Result<String, std::io::Error>{
    if packet.header.orig_len < TAG_PARAM_OFFSET as u32 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Packet too small"));
    }
    let mut cursor = TAG_PARAM_OFFSET;
    let tag_number = packet.data[cursor];

    if tag_number != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Not a beacon"));
    }

    cursor += 1;

    let tag_length = packet.data[cursor];

    cursor += 1;

    if tag_length == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Wildcard SSID. Skipping"));
    }

    let tag_value = &packet.data[cursor..cursor + tag_length as usize];

    // Print the tag value as a string
    let bssid = match std::str::from_utf8(tag_value) {
        Ok(v) => v,
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse tag value")),
    };

    Ok(bssid.to_string())
}

fn parse_ssid_from_probe(packet: &Packet) -> Result<String, std::io::Error> {
    let mut cursor = 40;
    let tag_number = packet.data[cursor];
    cursor += 1;

    if tag_number != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Not a probe"));
    }

    let tag_length = packet.data[cursor];
    cursor += 1;

    if tag_length == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Wildcard SSID. Skipping"));
    }

    let tag_value = &packet.data[cursor..cursor + tag_length as usize];

    // Get the tag value as a string
    let bssid = match std::str::from_utf8(tag_value) {
        Ok(v) => v,
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse tag value")),
    };

    Ok(bssid.to_string())
}

fn frequency_to_channel(channel: Channel) -> u8 {
    match channel.freq {
        2412 => 1,
        2417 => 2,
        2422 => 3,
        2427 => 4,
        2432 => 5,
        2437 => 6,
        2442 => 7,
        2447 => 8,
        2452 => 9,
        2457 => 10,
        2462 => 11,
        2467 => 12,
        2472 => 13,
        2484 => 14,
        _ => 0,
    }
}

fn get_packet_channel(packet: &Packet) -> u8 {
    let radiotap_header = match radiotap::Radiotap::from_bytes(&packet.data) {
        Ok(radiotap_header) => radiotap_header,
        Err(e) => {
            println!("error: {:?}", e);
            return 0;
        }
    };

    let channel = radiotap_header.channel.unwrap();
    let channel_num = frequency_to_channel(channel);

    return channel_num;
}