![Build](https://github.com/jakehomb/lime/actions/workflows/rust.yml/badge.svg)


# lime
Lime is a command line application for parsing the pcap from the wifi_coconut companion application

### Why
I am working primarily on windows/macbook and I don't have Kismet installed. The wifi_coconut software prints to stdout, or to a pcap file. If I want to access it live, I have to either get Kismet working on windows/mac or do a whole bunch of asspain. I had figured I could learn some more stuff in Rust while working on this.

## Objectives
- Parse out relevant data
    - SSID Broadcast
    - SSID Probe
    - Handshake (EAPOL)
- Provide access to the parsed data/result
    - gRPC is something I have been meaning to learn a bit more on. I will likely try to expose at least a gRPC interface for this.
    - REST api can also be implemented fairly easily for this as well. 

### Dependencies
Because I am writing a gRPC interface, the build steps are currently failing to compile the protobuf stuff. Will be fixed shortly