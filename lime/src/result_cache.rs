use lazy_static::lazy_static;
use std::sync::Mutex;
use std::collections::HashMap;
use lib_lime::bssid_information::BSSID;

lazy_static! {
    static ref DISCOVERED: Mutex<HashMap<String, BSSID>> = Mutex::new(HashMap::new());
}

pub fn cache_ssid(ssid: String) -> bool{
    let mut discovered = DISCOVERED.lock().unwrap();
    if !discovered.contains_key(&ssid) {
        let ssid_copy = ssid.clone();
        let bssid = BSSID::new(ssid);
        let ssid = bssid.get_ssid().clone().to_string();
        discovered.insert(ssid, bssid);
        
        println!("Discovered SSID: {}", ssid_copy);
        return false;
    } 
    return true;
}