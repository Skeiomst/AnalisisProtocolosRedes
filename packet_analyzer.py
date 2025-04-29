from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import BOOTP, DHCP
from dictionaries import *

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.current_index = 0

    def capture_packet(self, packet):
        """Captura y analiza un paquete en tiempo real"""
        self.packets.append(packet)
        return self.analyze_packet(packet)

    def analyze_packet(self, packet):
        """Analiza un paquete y extrae su información relevante"""
        packet_info = {
            'index': len(self.packets) - 1,
            'time': packet.time,
            'protocol': 'Unknown',
            'source': '',
            'destination': '',
            'length': len(packet),
            'info': ''
        }

        # Análisis de capa Ethernet
        if Ether in packet:
            packet_info['source_mac'] = packet[Ether].src
            packet_info['dest_mac'] = packet[Ether].dst

        # Análisis de ARP
        if ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['source'] = packet[ARP].psrc
            packet_info['destination'] = packet[ARP].pdst
            packet_info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}" if packet[ARP].op == 1 else \
                                f"Reply {packet[ARP].psrc} is at {packet[ARP].hwsrc}"

        # Análisis de IPv4
        elif IP in packet:
            packet_info['protocol'] = 'IPv4'
            packet_info['source'] = packet[IP].src
            packet_info['destination'] = packet[IP].dst
            packet_info['ttl'] = packet[IP].ttl
            packet_info['ip_checksum'] = packet[IP].chksum

            # TCP
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['source_port'] = packet[TCP].sport
                packet_info['dest_port'] = packet[TCP].dport
                packet_info['tcp_flags'] = self._get_tcp_flags(packet[TCP].flags)
                packet_info['tcp_checksum'] = packet[TCP].chksum
                
                # Clear Text Protocol Analysis
                if packet[TCP].sport in [21, 23, 25, 80, 110, 143] or packet[TCP].dport in [21, 23, 25, 80, 110, 143]:
                    protocol_map = {
                        21: 'FTP',
                        23: 'TELNET',
                        25: 'SMTP',
                        80: 'HTTP',
                        110: 'POP3',
                        143: 'IMAP'
                    }
                    port = packet[TCP].sport if packet[TCP].sport in protocol_map else packet[TCP].dport
                    packet_info['protocol'] = protocol_map[port]
                    if Raw in packet:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        packet_info['clear_text'] = payload
                        
                        if protocol_map[port] == 'HTTP':
                            # Parse HTTP headers
                            try:
                                headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", payload))
                                packet_info['http_headers'] = headers
                                first_line = payload.split('\r\n')[0]
                                packet_info['info'] = f"HTTP: {first_line}"
                            except:
                                packet_info['info'] = f"HTTP Data: {payload[:50]}..."
                        else:
                            packet_info['info'] = f"{protocol_map[port]} Data: {payload[:50]}..."
                else:
                    packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} [Flags: {packet_info['tcp_flags']}]"

            # UDP
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['source_port'] = packet[UDP].sport
                packet_info['dest_port'] = packet[UDP].dport
                packet_info['udp_checksum'] = packet[UDP].chksum
                
                # DNS Analysis
                if (packet[UDP].sport == 53 or packet[UDP].dport == 53) and packet.haslayer(DNS):
                    packet_info['protocol'] = 'DNS'
                    dns = packet[DNS]
                    packet_info['dns_id'] = dns.id
                    packet_info['dns_qr'] = 'Response' if dns.qr else 'Query'
                    packet_info['dns_opcode'] = dns.opcode
                    packet_info['dns_rcode'] = dns.rcode
                    
                    if dns.qr == 0:  # Query
                        if dns.qd:
                            qname = dns.qd.qname.decode('utf-8')
                            qtype = dns.qd.qtype
                            packet_info['info'] = f"DNS Query: {qname} (Type: {qtype})"
                    else:  # Response
                        answers = []
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            if hasattr(rr, 'rdata'):
                                answers.append(str(rr.rdata))
                        packet_info['info'] = f"DNS Response: {', '.join(answers)}"
                
                # DHCP Analysis
                elif (packet[UDP].sport in [67, 68] or packet[UDP].dport in [67, 68]) and packet.haslayer(BOOTP):
                    packet_info['protocol'] = 'DHCP'
                    dhcp = packet[BOOTP]
                    packet_info['dhcp_message_type'] = dhcp.op
                    packet_info['client_mac'] = dhcp.chaddr
                    if packet.haslayer(DHCP):
                        dhcp_options = packet[DHCP].options
                        message_type = next((opt[1] for opt in dhcp_options if opt[0] == 'message-type'), None)
                        requested_addr = next((opt[1] for opt in dhcp_options if opt[0] == 'requested_addr'), None)
                        packet_info['info'] = f"DHCP {['Discover', 'Offer', 'Request', 'ACK'][message_type-1] if message_type else 'Unknown'}"
                        if requested_addr:
                            packet_info['info'] += f" - Requested IP: {requested_addr}"
                
                # Clear Text Protocol Analysis
                elif packet[UDP].sport in [21, 23, 25, 80, 110, 143] or packet[UDP].dport in [21, 23, 25, 80, 110, 143]:
                    protocol_map = {
                        21: 'FTP',
                        23: 'TELNET',
                        25: 'SMTP',
                        80: 'HTTP',
                        110: 'POP3',
                        143: 'IMAP'
                    }
                    port = packet[UDP].sport if packet[UDP].sport in protocol_map else packet[UDP].dport
                    packet_info['protocol'] = protocol_map[port]
                    if Raw in packet:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        packet_info['clear_text'] = payload
                        packet_info['info'] = f"{protocol_map[port]} Data: {payload[:50]}..."
                
                else:
                    src_port_name = udp_ports_dict.get(packet[UDP].sport, str(packet[UDP].sport))
                    dst_port_name = udp_ports_dict.get(packet[UDP].dport, str(packet[UDP].dport))
                    packet_info['info'] = f"{src_port_name} → {dst_port_name}"

            # ICMPv4
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMPv4'
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                packet_info['icmp_type'] = icmp_type
                packet_info['icmp_code'] = icmp_code
                packet_info['icmp_checksum'] = packet[ICMP].chksum

                if icmp_type in icmpv4_dict:
                    type_info = icmpv4_dict[icmp_type]['name']
                    code_info = icmpv4_dict[icmp_type]['codes'].get(icmp_code, 'Unknown Code')
                    packet_info['info'] = f"Type: {type_info}, Code: {code_info}"
                else:
                    packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"

        # Análisis de IPv6
        elif IPv6 in packet:
            packet_info['protocol'] = 'IPv6'
            packet_info['source'] = packet[IPv6].src
            packet_info['destination'] = packet[IPv6].dst
            packet_info['traffic_class'] = packet[IPv6].tc
            packet_info['flow_label'] = packet[IPv6].fl

            # ICMPv6
            if any(layer in packet for layer in [ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA]):
                packet_info['protocol'] = 'ICMPv6'
                # Get the ICMPv6 layer
                icmpv6_layer = next(layer for layer in [ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA] if layer in packet)
                icmp_type = packet[icmpv6_layer].type
                icmp_code = packet[icmpv6_layer].code
                packet_info['icmp_type'] = icmp_type
                packet_info['icmp_code'] = icmp_code
                packet_info['icmp_checksum'] = packet[icmpv6_layer].cksum

                if icmp_type in icmpv6_dict:
                    type_info = icmpv6_dict[icmp_type]['name']
                    code_info = icmpv6_dict[icmp_type]['codes'].get(icmp_code, 'Unknown Code')
                    packet_info['info'] = f"Type: {type_info}, Code: {code_info}"
                else:
                    packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"

        return packet_info

    def _get_tcp_flags(self, flags):
        """Convierte los flags TCP a formato legible"""
        return ' '.join([tcp_flags_dict.get(f, f) for f in str(flags)])

    def get_packet(self, index):
        """Obtiene un paquete específico por su índice"""
        if 0 <= index < len(self.packets):
            return self.analyze_packet(self.packets[index])
        return None

    def get_packet_count(self):
        """Retorna el número total de paquetes capturados"""
        return len(self.packets)