use pcap_file::pcap::Packet;

pub mod parser;

pub fn is_beacon(packet: &Packet) -> bool {
    let frame_ctrl = packet.data[16];

    return frame_ctrl == 0x80;
}

pub fn is_probe(packet: &Packet) -> bool {
    let frame_ctrl = packet.data[16];

    return frame_ctrl == 0x40;
}

pub fn get_packet_channel(packet: &Packet) -> u8 {
    let radiotap_header = match radiotap::Radiotap::from_bytes(&packet.data) {
        Ok(radiotap_header) => radiotap_header,
        Err(e) => {
            println!("error: {:?}", e);
            return 0;
        }
    };

    let channel = radiotap_header.channel.unwrap();
    let channel_num = crate::channels::frequency_to_channel_24ghz(channel);

    return channel_num;
}