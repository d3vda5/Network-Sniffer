from scapy.all import *
import argparse
import sys

def packet_sniffer(interface, count):
    print(f"[*] Starting packet capture on interface {interface}...")
    
    # Sniff packets
    packets = sniff(iface=interface, count=count, prn=process_packet)
    
    print("[*] Packet capture completed.")

def process_packet(packet):
    # Print basic packet information
    print("\n[+] New Packet:")
    print(packet.summary())
    
    # Analyze specific layers (e.g., IP, TCP, UDP)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"   IP: {ip_src} -> {ip_dst}")
    
    if TCP in packet:
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"   TCP: {tcp_sport} -> {tcp_dport}")
    
    if UDP in packet:
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport
        print(f"   UDP: {udp_sport} -> {udp_dport}")
    
    # Print raw packet data (optional)
    print("   Raw Data:")
    print(packet.show(dump=True))


def get_arguments():
    parser = argparse.ArgumentParser(description="Python Network Sniffer")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to sniff on", required=True)
    parser.add_argument("-c", "--count", dest="count", type=int, help="Number of packets to capture", default=10)
    options = parser.parse_args()
    
    if not options.interface:
        parser.error("[-] Please specify a network interface. Use --help for more info.")
    
    return options

def main():
    options = get_arguments()
    packet_sniffer(options.interface, options.count)

if __name__ == "__main__":
    main()
