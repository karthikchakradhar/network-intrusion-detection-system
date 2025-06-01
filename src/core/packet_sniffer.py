from scapy.all import *
import logging
from datetime import datetime
from collections import defaultdict

class IDSSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.syn_count = defaultdict(int)
        self.icmp_count = defaultdict(int)
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids.log'),
                logging.StreamHandler()
            ]
        )
        
    def start_sniffing(self):
        sniff(iface=self.interface,
              prn=self.analyze_packet,
              filter="tcp or udp or icmp",
              store=False)
        
    def analyze_packet(self, packet):
        try:
            if packet.haslayer(IP):
                self.log_packet(packet)
                self.detect_port_scan(packet)
                self.detect_web_attacks(packet)
                self.detect_icmp_flood(packet)
                
        except Exception as e:
            logging.error(f"Packet processing error: {str(e)}")

    def log_packet(self, packet):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source': packet[IP].src,
            'destination': packet[IP].dst,
            'protocol': packet[IP].proto,
            'length': len(packet)
        }
        logging.info(f"Packet: {log_entry}")

    def detect_port_scan(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:  # SYN flag
            src_ip = packet[IP].src
            self.syn_count[src_ip] += 1
            
            if self.syn_count[src_ip] == 5:  # Threshold
                alert = f"Port scan detected from {src_ip}"
                logging.warning(alert)
                print(f"[!] {alert}")

    def detect_web_attacks(self, packet):
        if packet.haslayer(Raw):
            payload = str(packet[Raw].load).lower()
            threats = {
                'xss': ['<script>', 'javascript:', 'onload='],
                'sql_injection': ['1=1', "' or '1'='1", 'union select'],
                'rce': [';bash', '&&', '| ls']
            }
            
            for threat_type, patterns in threats.items():
                if any(pattern in payload for pattern in patterns):
                    alert = f"{threat_type.upper()} attempt from {packet[IP].src}"
                    logging.warning(f"{alert} - Payload snippet: {payload[:100]}")
                    print(f"[!] {alert}")

    def detect_icmp_flood(self, packet):
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            self.icmp_count[src_ip] += 1
            
            if self.icmp_count[src_ip] > 20:  # 20 ICMP packets
                alert = f"ICMP flood from {src_ip}"
                logging.warning(alert)
                print(f"[!] {alert}")