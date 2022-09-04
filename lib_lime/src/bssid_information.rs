use std::collections::HashSet;

pub struct BSSID {
    ssid: String,
    channels: HashSet<u8>,
}

impl BSSID {
    pub fn new(ssid: String) -> BSSID {
        BSSID {
            ssid: ssid,
            channels: HashSet::new(),
        }
    }

    pub fn get_ssid(&self) -> &String {
        &self.ssid
    }

    pub fn get_channels(&self) -> &HashSet<u8> {
        &self.channels
    }

    pub fn add_channel(&mut self, channel: u8) {
        self.channels.insert(channel);
    }
}

impl Default for BSSID {
    fn default() -> BSSID {
        BSSID {
            ssid: String::new(),
            channels: HashSet::new(),
        }
    }
}