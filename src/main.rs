use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use pnet::ipnetwork::IpNetwork;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};
use cidr::Ipv4Cidr;

use std::collections::HashMap;
use std::str;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};


// Static OUI database, Generated at build time
include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

/// Quick & dirty ARP scanner
#[derive(Parser, Debug)]
struct Args {
    /// Interface to send ARP requests on
    #[arg(short, long)]
    interface: String,

    /// CIDR network to scan (e.g., 192.168.1.0/24). If omitted, auto-detect.
    #[arg(short, long)]
    network: Option<String>,

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

    // Auto-detect CIDR network if not provided
    let network = args.network.unwrap_or_else(|| {
        iface.ips
            .iter()
            .find_map(|ip| match ip {
                IpNetwork::V4(v4net) => {
                    let net_addr: Ipv4Addr = v4net.network();   // <-- gives 10.2.150.0
                    let prefix = v4net.prefix();                // <-- gives 24
                    let cidr = Ipv4Cidr::new(net_addr, prefix)
                        .expect("Failed to build CIDR");
                    Some(cidr.to_string())
                }
                _ => None,
            })
            .expect("Interface has no IPv4 network")
    });

    let source_ip = match iface.ips.iter().find_map(|ip| match ip.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }) {
        Some(ip) => ip,
        None => {
            eprintln!("Error: Interface '{}' has no IPv4 address.", iface.name);
            std::process::exit(1);
        }
    };
    let (mut tx, rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open datalink channel: {e}"),
    };

    // Parse CIDR argument
    let cidr: Ipv4Cidr = network.parse().expect("Invalid CIDR");

    println!(
        "Scanning {} on interface {}...",
        network, args.interface
    );

    // Spawn a listener thread for replies
    let found_counter = Arc::new(AtomicUsize::new(0));
    let found_for_thread = Arc::clone(&found_counter);
    let listener = thread::spawn(move || listen_replies(rx, args.timeout, found_for_thread));

    // Send ARP requests
    for target_ip in cidr.iter().map(|inet| inet.address()) {
        if target_ip == source_ip {
            continue;
        }
        send_arp(&mut tx, source_mac, source_ip, target_ip, &iface);
        thread::sleep(Duration::from_millis(2)); // small throttle
    }

    // Wait for listener to finish
    listener.join().unwrap();

    // Print summary
    let total_found = found_counter.load(Ordering::SeqCst);
    println!("Scan complete. Found {} hosts.", total_found);
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
        eprintln!("send_to {} on iface {} failed: {e}", target_ip, iface.name);
    }
}

fn normalize_mac_prefix(mac: MacAddr) -> u32 {
    ((mac.0 as u32) << 16) | ((mac.1 as u32) << 8) | (mac.2 as u32)
}

fn listen_replies(
    mut rx: Box<dyn DataLinkReceiver>,
    timeout: u64,
    found_counter: Arc<AtomicUsize>,
) {
    // Build a HashMap from the generated static table
    let oui_map: HashMap<u32, &str> = OUI_TABLE.iter().cloned().collect();

    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(timeout) {
        match rx.next() {
            Ok(pkt) => {
                if let Some(eth) = EthernetPacket::new(pkt) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let sender_mac = arp.get_sender_hw_addr();
                                let prefix = normalize_mac_prefix(sender_mac);

                                let vendor = oui_map
                                    .get(&prefix)
                                    .copied() // turns Option<&&str> into Option<&str>
                                    .unwrap_or("Unknown Vendor");

                                println!(
                                    "{} is at {} ({})",
                                    arp.get_sender_proto_addr(),
                                    sender_mac,
                                    vendor
                                );

                                found_counter.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}
