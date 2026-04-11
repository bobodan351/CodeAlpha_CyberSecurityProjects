
"""
CodeAlpha_Task1_NetworkSniffer
Basic Network Packet Sniffer using Scapy with Multiple Storage Options
Author: Lawal Daniel Adebola (CodeAlpha)
Description: A simple network packet sniffer that captures and stores network traffic in various formats.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap
from datetime import datetime
import sys
import argparse
import json
import os
from colorama import init, Fore, Style

init(autoreset=True)

class NetworkSniffer:
    def __init__(self, interface=None, filter_protocol=None, count=0, 
                 output_dir="captures", save_format="all"):
        """
        Initialize the Network Sniffer
        
        Args:
            interface: Network interface to sniff on
            filter_protocol: BPF filter string
            count: Number of packets to capture (0 for infinite)
            output_dir: Directory to save captured files
            save_format: 'txt', 'pcap', 'json', 'all', or 'none'
        """
        self.interface = interface
        self.filter_protocol = filter_protocol
        self.count = count
        self.packet_count = 0
        self.output_dir = output_dir
        self.save_format = save_format
        
        # Storage containers
        self.captured_packets = []  # Raw scapy packets for PCAP
        self.packet_records = []    # JSON-serializable records
        self.log_content = []       # Text log lines
        
        # Setup output directory
        if save_format != 'none':
            self.setup_output_directory()
        
        # Protocol colors
        self.protocol_colors = {
            'TCP': Fore.BLUE, 'UDP': Fore.GREEN, 'ICMP': Fore.YELLOW,
            'ARP': Fore.MAGENTA, 'OTHER': Fore.WHITE
        }
        
        # Generate filename base with timestamp
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename_base = f"capture_{self.timestamp}"
    
    def setup_output_directory(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"{Fore.GREEN}[+] Created output directory: {self.output_dir}{Style.RESET_ALL}")
    
    def get_protocol_color(self, protocol):
        return self.protocol_colors.get(protocol, Fore.WHITE)
    
    def extract_packet_data(self, packet):
        """Extract structured data from packet for storage"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'packet_number': self.packet_count,
            'size_bytes': len(packet),
            'layers': {}
        }
        
        # Ethernet layer
        if hasattr(packet, 'src') and hasattr(packet, 'dst'):
            record['layers']['ethernet'] = {
                'src_mac': str(packet.src),
                'dst_mac': str(packet.dst)
            }
        
        # IP Layer
        if IP in packet:
            ip = packet[IP]
            record['layers']['ip'] = {
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ttl': ip.ttl,
                'protocol_num': ip.proto,
                'version': ip.version
            }
            
            # Transport layer
            if TCP in packet:
                tcp = packet[TCP]
                record['layers']['tcp'] = {
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'flags': str(tcp.flags),
                    'window': tcp.window
                }
                record['protocol'] = 'TCP'
                
            elif UDP in packet:
                udp = packet[UDP]
                record['layers']['udp'] = {
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'length': udp.len
                }
                record['protocol'] = 'UDP'
                
            elif ICMP in packet:
                icmp = packet[ICMP]
                record['layers']['icmp'] = {
                    'type': icmp.type,
                    'code': icmp.code,
                    'id': icmp.id if hasattr(icmp, 'id') else None,
                    'seq': icmp.seq if hasattr(icmp, 'seq') else None
                }
                record['protocol'] = 'ICMP'
            else:
                record['protocol'] = f'Other({ip.proto})'
                
        elif ARP in packet:
            arp = packet[ARP]
            record['layers']['arp'] = {
                'op': 'Request' if arp.op == 1 else 'Reply',
                'src_mac': arp.hwsrc,
                'src_ip': arp.psrc,
                'dst_mac': arp.hwdst,
                'dst_ip': arp.pdst
            }
            record['protocol'] = 'ARP'
        else:
            record['protocol'] = 'Unknown'
        
        # Payload
        if Raw in packet:
            payload = packet[Raw].load
            record['payload'] = {
                'size': len(payload),
                'hex': payload.hex()[:200],  # First 100 bytes as hex
                'ascii': repr(payload[:100])  # First 100 chars
            }
        else:
            record['payload'] = None
            
        return record
    
    def format_packet_info(self, packet):
        """Format packet information for console display"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.packet_count += 1
        
        output = []
        output.append(f"\n{'='*70}")
        output.append(f"{Fore.CYAN}Packet #{self.packet_count} | {timestamp} | {len(packet)} bytes{Style.RESET_ALL}")
        output.append(f"{'='*70}")
        
        # Extract data for both display and storage
        packet_data = self.extract_packet_data(packet)
        
        # Store for JSON
        if self.save_format in ['json', 'all']:
            self.packet_records.append(packet_data)
        
        # MAC Layer
        if 'ethernet' in packet_data['layers']:
            eth = packet_data['layers']['ethernet']
            output.append(f"{'MAC Source:':<20} {eth['src_mac']}")
            output.append(f"{'MAC Destination:':<20} {eth['dst_mac']}")
        
        # IP Layer
        if 'ip' in packet_data['layers']:
            ip = packet_data['layers']['ip']
            proto = packet_data['protocol']
            color = self.get_protocol_color(proto.split('(')[0] if '(' in proto else proto)
            
            output.append(f"\n{color}[IP Layer]{Style.RESET_ALL}")
            output.append(f"{'Source IP:':<20} {ip['src_ip']}")
            output.append(f"{'Destination IP:':<20} {ip['dst_ip']}")
            output.append(f"{'TTL:':<20} {ip['ttl']}")
            output.append(f"{'Protocol:':<20} {proto}")
            
            # TCP
            if 'tcp' in packet_data['layers']:
                tcp = packet_data['layers']['tcp']
                output.append(f"\n{color}[TCP Layer]{Style.RESET_ALL}")
                output.append(f"{'Source Port:':<20} {tcp['src_port']}")
                output.append(f"{'Destination Port:':<20} {tcp['dst_port']}")
                output.append(f"{'Flags:':<20} {tcp['flags']}")
                service = self.detect_service(tcp['dst_port'])
                if service:
                    output.append(f"{'Service:':<20} {Fore.YELLOW}{service}{Style.RESET_ALL}")
            
            # UDP
            elif 'udp' in packet_data['layers']:
                udp = packet_data['layers']['udp']
                output.append(f"\n{color}[UDP Layer]{Style.RESET_ALL}")
                output.append(f"{'Source Port:':<20} {udp['src_port']}")
                output.append(f"{'Destination Port:':<20} {udp['dst_port']}")
                service = self.detect_service(udp['dst_port'])
                if service:
                    output.append(f"{'Service:':<20} {Fore.YELLOW}{service}{Style.RESET_ALL}")
            
            # ICMP
            elif 'icmp' in packet_data['layers']:
                icmp = packet_data['layers']['icmp']
                output.append(f"\n{color}[ICMP Layer]{Style.RESET_ALL}")
                output.append(f"{'Type:':<20} {icmp['type']} ({self.get_icmp_desc(icmp['type'])})")
                output.append(f"{'Code:':<20} {icmp['code']}")
        
        # ARP
        elif 'arp' in packet_data['layers']:
            arp = packet_data['layers']['arp']
            color = self.get_protocol_color('ARP')
            output.append(f"\n{color}[ARP Layer]{Style.RESET_ALL}")
            output.append(f"{'Operation:':<20} {arp['op']}")
            output.append(f"{'Sender:':<20} {arp['src_mac']} / {arp['src_ip']}")
            output.append(f"{'Target:':<20} {arp['dst_mac']} / {arp['dst_ip']}")
        
        # Payload
        if packet_data['payload']:
            output.append(f"\n{Fore.WHITE}[Payload]{Style.RESET_ALL}")
            output.append(f"{'Size:':<20} {packet_data['payload']['size']} bytes")
            if packet_data['payload']['ascii']:
                output.append(f"{'Data:':<20} {packet_data['payload']['ascii'][:80]}")
        
        output.append(f"{'='*70}")
        
        # Store for text log
        log_entry = '\n'.join(output)
        if self.save_format in ['txt', 'all']:
            self.log_content.append(log_entry)
        
        return log_entry
    
    def detect_service(self, port):
        """Detect common services"""
        services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 
            3389: 'RDP', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        return services.get(port, None)
    
    def get_icmp_desc(self, icmp_type):
        """ICMP type descriptions"""
        types = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
        return types.get(icmp_type, 'Unknown')
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        try:
            # Display in console
            info = self.format_packet_info(packet)
            print(info)
            
            # Store raw packet for PCAP export
            if self.save_format in ['pcap', 'all']:
                self.captured_packets.append(packet)
                
        except Exception as e:
            print(f"{Fore.RED}Error processing packet: {e}{Style.RESET_ALL}")
    
    def save_files(self):
        """Save captured data to files"""
        if self.save_format == 'none':
            return
            
        print(f"\n{Fore.CYAN}[*] Saving captured data...{Style.RESET_ALL}")
        
        # 1. Save as PCAP (Wireshark compatible)
        if self.save_format in ['pcap', 'all'] and self.captured_packets:
            pcap_path = os.path.join(self.output_dir, f"{self.filename_base}.pcap")
            wrpcap(pcap_path, self.captured_packets)
            print(f"{Fore.GREEN}[+] PCAP saved: {pcap_path}{Style.RESET_ALL}")
            print(f"    Open in Wireshark: wireshark {pcap_path}")
        
        # 2. Save as JSON (structured data)
        if self.save_format in ['json', 'all'] and self.packet_records:
            json_path = os.path.join(self.output_dir, f"{self.filename_base}.json")
            with open(json_path, 'w') as f:
                json.dump({
                    'capture_info': {
                        'timestamp': self.timestamp,
                        'interface': self.interface or 'default',
                        'filter': self.filter_protocol or 'none',
                        'total_packets': self.packet_count
                    },
                    'packets': self.packet_records
                }, f, indent=2)
            print(f"{Fore.GREEN}[+] JSON saved: {json_path}{Style.RESET_ALL}")
        
        # 3. Save as Text Log (human readable)
        if self.save_format in ['txt', 'all'] and self.log_content:
            txt_path = os.path.join(self.output_dir, f"{self.filename_base}.txt")
            with open(txt_path, 'w') as f:
                f.write(f"CodeAlpha Network Sniffer - Capture Log\n")
                f.write(f"Timestamp: {self.timestamp}\n")
                f.write(f"Interface: {self.interface or 'default'}\n")
                f.write(f"Filter: {self.filter_protocol or 'none'}\n")
                f.write(f"Total Packets: {self.packet_count}\n")
                f.write("="*70 + "\n")
                f.write('\n'.join(self.log_content))
            print(f"{Fore.GREEN}[+] Text log saved: {txt_path}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}[*] All files saved in: {os.path.abspath(self.output_dir)}{Style.RESET_ALL}")
    
    def start_sniffing(self):
        """Start packet capture"""
        print(f"{Fore.GREEN}{'='*70}")
        print(f"CodeAlpha Network Sniffer")
        print(f"{'='*70}")
        print(f"Output Directory: {self.output_dir}")
        print(f"Save Format: {self.save_format}")
        print(f"Interface: {self.interface or 'Default'}")
        print(f"Filter: {self.filter_protocol or 'All protocols'}")
        print(f"Count: {'Unlimited' if self.count == 0 else self.count}")
        print(f"Press Ctrl+C to stop and save...")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_protocol,
                prn=self.packet_handler,
                count=self.count,
                store=0
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Capture stopped by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        finally:
            # Always save on exit
            self.save_files()
            print(f"{Fore.GREEN}[*] Total packets captured: {self.packet_count}{Style.RESET_ALL}")


def list_interfaces():
    from scapy.all import get_if_list, get_if_addr
    print(f"{Fore.CYAN}Available Interfaces:{Style.RESET_ALL}")
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
            print(f"  - {iface}: {addr if addr else 'No IP'}")
        except:
            print(f"  - {iface}")


def main():
    parser = argparse.ArgumentParser(
        description='CodeAlpha Network Sniffer with File Storage',
        epilog="""
Storage Options:
  --save-format txt    Human-readable text log only
  --save-format pcap   Wireshark-compatible PCAP only  
  --save-format json   Structured JSON data only
  --save-format all    All formats (default)
  --save-format none   Display only, don't save files

Examples:
  sudo python3 codealpha-net-sniffler.py --save-format pcap -f tcp
  sudo python3 codealpha-net-sniffler.py -o my_captures -c 100
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface')
    parser.add_argument('-f', '--filter', help='BPF filter (tcp, udp, port 80)')
    parser.add_argument('-c', '--count', type=int, default=0, help='Packet count')
    parser.add_argument('-o', '--output', default='captures', help='Output directory')
    parser.add_argument('-s', '--save-format', default='all', 
                       choices=['txt', 'pcap', 'json', 'all', 'none'],
                       help='Save format')
    parser.add_argument('-l', '--list', action='store_true', help='List interfaces')
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        return
    
    # Check root
    import os
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: Requires sudo/root access{Style.RESET_ALL}")
        sys.exit(1)
    
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_protocol=args.filter,
        count=args.count,
        output_dir=args.output,
        save_format=args.save_format
    )
    
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()