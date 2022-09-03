
pub struct BSSID {
    ssid: String,
    channel_num: u8,
}

impl BSSID {
    pub fn new(ssid: String) -> BSSID {
        BSSID {
            ssid: ssid,
            channel_num: 0,
        }
    }

    pub fn get_ssid(&self) -> &String {
        &self.ssid
    }

    pub fn get_channel_num(&self) -> u8 {
        self.channel_num
    }
}

impl Default for BSSID {
    fn default() -> BSSID {
        BSSID {
            ssid: String::new(),
            channel_num: 0,
        }
    }
}