#!/usr/bin/env python3

import scapy.all as scapy
from datetime import datetime
import sys
import logging
import argparse
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init()

class PacketAnalyzer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.packet_stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'Other': 0
        }
        self.setup_logging()

    def setup_logging(self):
        """Configure secure logging"""
        logging.basicConfig(
            filename=f'packet_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        # Analyze packet type
        if packet.haslayer(scapy.TCP):
            self.packet_stats['TCP'] += 1
            self.analyze_tcp(packet)
        elif packet.haslayer(scapy.UDP):
            self.packet_stats['UDP'] += 1
            self.analyze_udp(packet)
        elif packet.haslayer(scapy.ICMP):
            self.packet_stats['ICMP'] += 1
            self.analyze_icmp(packet)
        else:
            self.packet_stats['Other'] += 1

    def analyze_tcp(self, packet):
        """Analyze TCP packets"""
        try:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            
            print(f"{Fore.GREEN}[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Style.RESET_ALL}")
            logging.info(f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
        except Exception as e:
            logging.error(f"Error analyzing TCP packet: {str(e)}")

    def analyze_udp(self, packet):
        """Analyze UDP packets"""
        try:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            
            print(f"{Fore.YELLOW}[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Style.RESET_ALL}")
            logging.info(f"UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
        except Exception as e:
            logging.error(f"Error analyzing UDP packet: {str(e)}")

    def analyze_icmp(self, packet):
        """Analyze ICMP packets"""
        try:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            print(f"{Fore.BLUE}[ICMP] {src_ip} -> {dst_ip}{Style.RESET_ALL}")
            logging.info(f"ICMP: {src_ip} -> {dst_ip}")
            
        except Exception as e:
            logging.error(f"Error analyzing ICMP packet: {str(e)}")

    def start_capture(self, packet_count=None):
        """Start packet capture"""
        print(f"{Fore.CYAN}[*] Starting packet capture...{Style.RESET_ALL}")
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=packet_count,
                store=0
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Capture stopped by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Capture error: {str(e)}")
            sys.exit(1)

    def print_stats(self):
        """Display capture statistics"""
        print(f"\n{Fore.CYAN}=== Packet Statistics ==={Style.RESET_ALL}")
        print(f"Total Packets: {self.packet_count}")
        print(f"TCP Packets:  {self.packet_stats['TCP']}")
        print(f"UDP Packets:  {self.packet_stats['UDP']}")
        print(f"ICMP Packets: {self.packet_stats['ICMP']}")
        print(f"Other:        {self.packet_stats['Other']}")

def check_root():
    """Check for root privileges"""
    if sys.platform.startswith('win'):
        return True
    return os.geteuid() == 0

def main():
    """Main function"""
    if not check_root():
        print(f"{Fore.RED}[!] This script requires root privileges{Style.RESET_ALL}")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Simple Network Packet Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to capture')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    args = parser.parse_args()

    try:
        analyzer = PacketAnalyzer(interface=args.interface)
        print(f"{Fore.GREEN}[+] Packet Analyzer initialized{Style.RESET_ALL}")
        print(f"[*] Interface: {args.interface or 'default'}")
        print(f"[*] Packet count: {args.count or 'unlimited'}")
        
        analyzer.start_capture(packet_count=args.count)
        analyzer.print_stats()
        
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()