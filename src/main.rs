use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};
use cidr::Ipv4Cidr;

use std::collections::HashMap;
use std::str;

// Static OUI database
const OUI_CSV: &[u8] = include_bytes!("../data/mac-vendors-export.csv");

/// Parses the embedded CSV into a HashMap of prefix → vendor
fn parse_oui() -> HashMap<String, String> {
    let mut map = HashMap::new();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(OUI_CSV);

    for result in rdr.records() {
        if let Ok(record) = result {
            // record[0] = "00:01:E5"
            // record[1] = "Supernet, Inc."
            let prefix = record[0].to_ascii_uppercase().replace(':', "");
            let vendor = record[1].to_string();
            map.insert(prefix, vendor);
        }
    }

    map
}

/// Quick & dirty ARP scanner
#[derive(Parser, Debug)]
struct Args {
    /// Interface to send ARP requests on
    #[arg(short, long)]
    interface: String,

    /// CIDR network to scan (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    network: String,

    /// Timeout (seconds) to wait for replies
    #[arg(short, long, default_value_t = 3)]
    timeout: u64,
}

fn main() {
    let args = Args::parse();

    // Find interface by name
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == args.interface)
        .unwrap_or_else(|| panic!("Interface {} not found", args.interface));

    let source_mac = iface.mac.expect("Interface has no MAC");
    let source_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .expect("Interface has no IPv4 address");


    let (mut tx, rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open datalink channel: {e}"),
    };

    // Parse CIDR argument
    let cidr: Ipv4Cidr = args.network.parse().expect("Invalid CIDR");
   let hosts: Vec<Ipv4Addr> = cidr.iter().map(|inet| inet.address()).collect();

    // Spawn a listener thread for replies
    let listener = thread::spawn(move || listen_replies(rx, args.timeout));

    // Send ARP requests
    for target_ip in hosts {
        if target_ip == source_ip {
            continue;
        }
        send_arp(&mut tx, source_mac, source_ip, target_ip, &iface);
        thread::sleep(Duration::from_millis(2)); // small throttle
    }

    // Wait for listener to finish
    listener.join().unwrap();
}

fn send_arp(
    tx: &mut Box<dyn DataLinkSender>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    iface: &NetworkInterface,
) {
    let mut buf = [0u8; 42];

    let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(source_mac);
    eth.set_ethertype(EtherTypes::Arp);

    {
        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    if let Some(Err(e)) = tx.send_to(eth.packet(), Some(iface.clone())) {
        eprintln!("send_to {} failed: {e}", target_ip);
    }
}

fn listen_replies(mut rx: Box<dyn DataLinkReceiver>, timeout: u64) {
    let oui_map = parse_oui();
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(timeout) {
        match rx.next() {
            Ok(pkt) => {
                if let Some(eth) = EthernetPacket::new(pkt) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let sender_mac = arp.get_sender_hw_addr();
                                let vendor = oui_map
                                    .get(&normalize_mac_prefix(sender_mac))
                                    .map(|s| s.as_str())
                                    .unwrap_or("Unknown Vendor");

                                println!(
                                    "{} is at {} ({})",
                                    arp.get_sender_proto_addr(),
                                    sender_mac,
                                    vendor
                                );
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}

/// Normalize MAC → 6 hex chars (OUI prefix)
fn normalize_mac_prefix(mac: MacAddr) -> String {
    let full = mac.to_string().replace(':', "").to_ascii_uppercase();
    full[..6].to_string()
}
