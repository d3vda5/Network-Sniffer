# Network Sniffer

This Python program is a simple network sniffer that captures and analyzes network packets on a specified network interface. It uses the `scapy` library to perform packet sniffing and analysis.

## Features

- Captures network packets on a specified interface.
- Analyzes and displays information about IP, TCP, and UDP packets.
- Prints raw packet data for detailed inspection.

## Usage

To run the network sniffer, use the following command:

```bash
sudo python Network_sniffer.py -i <interface> -c <count>
```

* `<interface>`: The network interface to sniff on (e.g., eth0, wlan0).
* `<count>`: The number of packets to capture (default is 10).

## Example
```sh
sudo python Network_sniffer.py -i eth0 -c 20
```
This command will start capturing 20 packets on the `eth0` interface.

##Output

The program will display information about each captured packet, including:

* Basic packet summary.
* Source and destination IP addresses.
* Source and destination ports for TCP and UDP packets.
* Raw packet data (optional).

## Sample Output

```bash
[*] Starting packet capture on interface eth0...

[+] New Packet:
Ether / IP / TCP 192.168.1.2:12345 > 192.168.1.1:80 S
   IP: 192.168.1.2 -> 192.168.1.1
   TCP: 12345 -> 80
   Raw Data:
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:0c:29:68:22:1b
  type      = 0x800
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 1
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x1c46
     src       = 192.168.1.2
     dst       = 192.168.1.1
###[ TCP ]###
        sport     = 12345
        dport     = 80
        seq       = 0
        ack       = 0
        dataofs   = 5
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = 0x1c46
        urgptr    = 0
```
This output shows a captured TCP packet with detailed information about its Ethernet, IP, and TCP layers. 