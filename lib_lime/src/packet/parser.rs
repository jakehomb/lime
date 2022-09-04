use pcap_file::pcap::Packet;

const TAG_PARAM_OFFSET_BEACON : usize = 52;
const TAG_PARAM_OFFSET_PROBE : usize = 40;

pub fn parse_ssid_from_beacon(packet: &Packet) -> Result<String, std::io::Error>{
    if packet.header.orig_len < TAG_PARAM_OFFSET_BEACON as u32 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Packet too small"));
    }
    
    return parse_ssid_tag(packet, TAG_PARAM_OFFSET_BEACON);
}

pub fn parse_ssid_from_probe(packet: &Packet) -> Result<String, std::io::Error> {
    if packet.header.orig_len < TAG_PARAM_OFFSET_PROBE as u32 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Packet too small"));
    }

    return parse_ssid_tag(packet, TAG_PARAM_OFFSET_PROBE);
    
}


fn parse_ssid_tag(packet: &Packet, offset: usize) -> Result<String, std::io::Error> {
    let mut cursor = offset;

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
