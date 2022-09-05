use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref BROADCAST: Mutex<HashMap<String, crate::api::server::lime::BroadcastSsid>> = Mutex::new(HashMap::new());
    static ref PROBES: Mutex<HashMap<String, crate::api::server::lime::ProbeSsid>> = Mutex::new(HashMap::new());
    static ref HANDSHAKES: Mutex<HashMap<String, crate::api::server::lime::Handshake>> = Mutex::new(HashMap::new());
}

#[allow(dead_code)]
pub fn cache_bssid(bssid: String) -> bool{
    let mut broadcast = BROADCAST.lock().unwrap();
    if !broadcast.contains_key(&bssid) {
        broadcast.insert(bssid.clone(), crate::api::server::lime::BroadcastSsid {
            ssid: bssid.clone(),
            channel: 1,
        });
        return false;
    } 
    return true;
}

#[allow(dead_code)]
pub fn cache_probe(bssid: String) -> bool {
    let mut probes = PROBES.lock().unwrap();
    if !probes.contains_key(&bssid) {
        probes.insert(bssid.clone(), crate::api::server::lime::ProbeSsid {
            ssid: bssid.clone(),
            channel: 1,
        });
        return false;
    } 
    return true;
}

#[allow(dead_code)]
pub fn cache_handshake(bssid: String) -> bool {
    let mut handshakes = HANDSHAKES.lock().unwrap();
    if !handshakes.contains_key(&bssid) {
        handshakes.insert(bssid.clone(), crate::api::server::lime::Handshake {
            ssid: bssid.clone(),
            eapol: "test_eapol".to_string(),
        });
        return false;
    } 
    return true;
}

#[allow(dead_code)]
pub fn get_bssid_count() -> usize {
    let broadcast = BROADCAST.lock().unwrap();
    return broadcast.len();
}

#[allow(dead_code)]
pub fn get_probe_count() -> usize {
    let probes = PROBES.lock().unwrap();
    return probes.len();
}

#[allow(dead_code)]
pub fn get_handshake_count() -> usize {
    let handshakes = HANDSHAKES.lock().unwrap();
    return handshakes.len();
}

pub fn get_bssids() -> Vec<crate::api::server::lime::BroadcastSsid> {
    let broadcast = BROADCAST.lock().unwrap();
    let mut result = Vec::new();
    for (_, value) in broadcast.iter() {
        result.push(value.clone());
    }
    return result;
}

#[allow(dead_code)]
pub fn get_bssid_list() -> Vec<String> {
    let broadcast = BROADCAST.lock().unwrap();
    let mut bssid_list: Vec<String> = Vec::new();
    for (key, _value) in broadcast.iter() {
        bssid_list.push(key.clone());
    }
    return bssid_list;
}

#[allow(dead_code)]
pub fn get_probe_list() -> Vec<String> {
    let probes = PROBES.lock().unwrap();
    let mut probe_list: Vec<String> = Vec::new();
    for (key, _value) in probes.iter() {
        probe_list.push(key.clone());
    }
    return probe_list;
}

pub fn get_probes() -> Vec<crate::api::server::lime::ProbeSsid> {
    let probes = PROBES.lock().unwrap();
    let mut result = Vec::new();
    for (_, value) in probes.iter() {
        result.push(value.clone());
    }
    return result;
}

#[allow(dead_code)]
pub fn get_handshake_list() -> Vec<String> {
    let handshakes = HANDSHAKES.lock().unwrap();
    let mut handshake_list: Vec<String> = Vec::new();
    for (key, _value) in handshakes.iter() {
        handshake_list.push(key.clone());
    }
    return handshake_list;
}


pub fn add_bssid(bssid: String) {
    let mut broadcast = BROADCAST.lock().unwrap();
    broadcast.insert(bssid.clone(), crate::api::server::lime::BroadcastSsid {
        ssid: bssid.clone(),
        channel: 1,
    });
}

pub fn add_probe(bssid: String) {
    let mut probes = PROBES.lock().unwrap();
    probes.insert(bssid.clone(), crate::api::server::lime::ProbeSsid {
        ssid: bssid.clone(),
        channel: 1,
    });
}

pub fn add_handshake(bssid: String) {
    let mut handshakes = HANDSHAKES.lock().unwrap();
    handshakes.insert(bssid.clone(), crate::api::server::lime::Handshake {
        ssid: bssid.clone(),
        eapol: "test_eapol".to_string(),
    });
}