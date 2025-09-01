# arp-scan (Rust)

A tiny, fast ARP scanner written in Rust. It sweeps an IPv4 CIDR on a given interface using raw Ethernet ARP requests and prints hosts that reply, including an estimated vendor name from an embedded OUI database.

> **Note:** This tool operates at Layer 2 and must be run on the same broadcast domain as the targets. Administrator/root privileges are required to create raw sockets and send Ethernet frames.

-----

## ✨ Features

  * **Simple ARP Sweep**: Scans an entire IPv4 CIDR range.
  * **Layer 2 Operation**: Discovers hosts directly via ARP, no ICMP/ping required.
  * **Vendor Lookup**: Identifies device manufacturers using an embedded OUI database.
  * **Lightweight**: Minimal dependencies and a small footprint.
  * **Controlled Speed**: Includes a small throttle to avoid flooding the network.

-----

## 🚀 Quick Start

**Prerequisites:**

  * Linux (or another OS supported by `pnet` for raw sockets).
  * Rust toolchain (via `rustup`).
  * An active network interface on the target LAN.

**1. Build the binary:**

```bash
cargo build --release
```

**2. Run the scan (requires sudo/root):**

```bash
sudo ./target/release/arp-scan \
  --interface eth0 \
  --network 192.168.1.0/24
```

-----

## usage

The tool requires an interface and a network range. You can also specify a custom timeout.

### Command-Line Options

| Flag                     | Description                                            | Default |
| ------------------------ | ------------------------------------------------------ | ------- |
| `-i`, `--interface <IF>` | Network interface to use (e.g., `eth0`, `enp3s0`).     | (none)  |
| `-n`, `--network <CIDR>` | IPv4 network in CIDR notation (e.g., `192.168.1.0/24`). | (none)  |
| `-t`, `--timeout <SEC>`  | Seconds to wait for replies after sending all packets.  | `3`     |

### Example Output

Running a scan will produce a list of active hosts found on the local network. The MAC addresses are anonymized below to only show the vendor-specific OUI.

```bash
$ sudo ./target/release/arp-scan --interface enp5s0 --network 192.168.1.0/24 --timeout 2

Scanning 192.168.1.0/24 on interface enp5s0...
192.168.1.1 is at 74:4d:28:XX:XX:XX (Routerboard.com)
192.168.1.32 is at cc:88:26:XX:XX:XX (LG Innotek)
192.168.1.45 is at 3c:7c:3f:XX:XX:XX (ASUSTek COMPUTER INC.)
192.168.1.48 is at c8:7f:54:XX:XX:XX (ASUSTek COMPUTER INC.)
192.168.1.105 is at 58:47:ca:XX:XX:XX (IEEE Registration Authority)
Scan complete. Found 5 hosts.
```

-----

## ⚙️ How It Works

1.  Opens a raw Layer 2 datalink channel on the specified interface using the `pnet` crate.
2.  Iterates through every IP address in the target CIDR.
3.  For each IP, it constructs and broadcasts an ARP request frame asking "Who has this IP address?".
4.  It then listens for incoming ARP replies until the timeout is reached.
5.  For each valid reply, it prints the IP, MAC address, and the corresponding vendor looked up from an embedded OUI CSV file.

-----

## ⚠️ Limitations

  * **IPv4 Only**: Does not support IPv6 or Neighbor Discovery Protocol.
  * **Same Broadcast Domain**: The scanner must be on the same L2 network segment as the targets.
  * **Requires Privileges**: Needs `sudo` or root access to open raw sockets.
  * **Static OUI Database**: The vendor mapping is based on a CSV file compiled into the binary and may become outdated.
  * **Stealthy Hosts**: Devices configured to ignore broadcast ARP requests will not be detected.

-----

## 📦 Vendor Data

The OUI database is embedded at build time from `data/mac-vendors-export.csv`. To update the vendor list, simply replace this file with a newer version and rebuild the project with `cargo build --release`.

-----

## Attribution

  * Fully developed by ChatGPT-5 at the author’s request.
  * Includes a static vendor OUI CSV under `data/`.
