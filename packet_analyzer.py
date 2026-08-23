# Importación de módulos necesarios de Scapy para el análisis de paquetes
from scapy.all import *  # Importa todas las funcionalidades principales de Scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP  # Importa clases para protocolos IPv4
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA  # Importa clases para IPv6
from scapy.layers.l2 import ARP  # Importa clase para el protocolo ARP
from scapy.layers.dns import DNS  # Importa clase para análisis DNS
from scapy.layers.dhcp import BOOTP, DHCP  # Importa clases para análisis DHCP
from dictionaries import *  # Importa diccionarios de constantes y mapeos

class PacketAnalyzer:
    """Clase principal para el análisis y procesamiento de paquetes de red.
    Proporciona funcionalidades para capturar, analizar y almacenar información de paquetes de red."""

    def __init__(self):
        """Constructor de la clase. Inicializa las estructuras de datos necesarias para el análisis.
        - packets: Lista para almacenar todos los paquetes capturados
        - current_index: Contador para el índice actual de paquetes
        - protocol_packets: Diccionario para almacenar paquetes únicos por protocolo
        - start_time: Tiempo de inicio de la captura"""
        self.packets = []  # Almacena todos los paquetes capturados
        self.current_index = 0  # Índice para el seguimiento de paquetes
        self.protocol_packets = {}  # Almacena un paquete por cada tipo de protocolo
        self.start_time = None  # Marca de tiempo inicial de la captura

    def capture_packet(self, packet):
        """Captura y procesa un nuevo paquete.
        Args:
            packet: Paquete de red capturado por Scapy
        Returns:
            dict: Información analizada del paquete"""
        self.packets.append(packet)  # Añade el paquete a la lista
        packet_info = self.analyze_packet(packet)  # Analiza el paquete
        self.current_index += 1  # Incrementa el contador de paquetes
        return packet_info

    def capture_unique_protocol_packet(self, packet):
        """Captura un paquete solo si su protocolo no ha sido registrado previamente.
        Args:
            packet: Paquete de red capturado
        Returns:
            dict: Información del paquete si es único, None en caso contrario"""
        packet_info = self.analyze_packet(packet)
        protocol = packet_info['protocol']
        
        if protocol not in self.protocol_packets:  # Verifica si es un protocolo nuevo
            self.protocol_packets[protocol] = packet_info
            self.current_index += 1
            return packet_info
        return None

    def clear_packets(self):
        """Limpia todas las estructuras de datos de paquetes capturados.
        Reinicia los contadores y el tiempo inicial."""
        self.packets = []  # Limpia la lista de paquetes
        self.protocol_packets = {}  # Limpia el diccionario de protocolos
        self.current_index = 0  # Reinicia el contador
        self.start_time = None  # Reinicia el tiempo inicial

    def analyze_packet(self, packet):
        """Analiza un paquete y extrae su información relevante.
        Args:
            packet: Paquete de red a analizar
        Returns:
            dict: Diccionario con la información detallada del paquete"""
        # Inicialización del tiempo relativo
        if self.start_time is None:
            self.start_time = packet.time
        relative_time = packet.time - self.start_time
        
        # Estructura básica de información del paquete
        packet_info = {
            'index': self.current_index,
            'time': relative_time,
            'protocol': 'Unknown',
            'source': '',
            'destination': '',
            'length': len(packet),
            'info': ''
        }

        # Análisis de la capa Ethernet
        if Ether in packet:
            packet_info['source_mac'] = packet[Ether].src  # Dirección MAC origen
            packet_info['dest_mac'] = packet[Ether].dst    # Dirección MAC destino

        # Análisis de protocolo ARP
        if ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['source'] = packet[ARP].psrc  # IP origen
            packet_info['destination'] = packet[ARP].pdst  # IP destino
            # Formato del mensaje ARP (pregunta o respuesta)
            packet_info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}" if packet[ARP].op == 1 else \
                                f"Reply {packet[ARP].psrc} is at {packet[ARP].hwsrc}"

        # Análisis de paquetes IPv4
        elif IP in packet:
            packet_info['protocol'] = 'IPv4'
            packet_info['source'] = packet[IP].src  # IP origen
            packet_info['destination'] = packet[IP].dst  # IP destino
            packet_info['ttl'] = packet[IP].ttl  # Tiempo de vida
            packet_info['ip_checksum'] = packet[IP].chksum  # Suma de verificación

            # Análisis de TCP
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['source_port'] = packet[TCP].sport  # Puerto origen
                packet_info['dest_port'] = packet[TCP].dport    # Puerto destino
                packet_info['tcp_flags'] = self._get_tcp_flags(packet[TCP].flags)  # Banderas TCP
                packet_info['tcp_checksum'] = packet[TCP].chksum  # Suma de verificación TCP
                
                # Análisis de protocolos de texto claro sobre TCP
                if packet[TCP].sport in [21, 23, 25, 80, 110, 143] or packet[TCP].dport in [21, 23, 25, 80, 110, 143]:
                    # Mapeo de puertos a protocolos
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
                    
                    # Análisis de datos en texto claro
                    if Raw in packet:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        packet_info['clear_text'] = payload
                        
                        # Análisis específico para HTTP
                        if protocol_map[port] == 'HTTP':
                            try:
                                # Extracción de cabeceras HTTP
                                headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", payload))
                                packet_info['http_headers'] = headers
                                first_line = payload.split('\r\n')[0]
                                packet_info['info'] = f"HTTP: {first_line}"
                            except:
                                packet_info['info'] = f"HTTP Data: {payload[:50]}..."
                        else:
                            packet_info['info'] = f"{protocol_map[port]} Data: {payload[:50]}..."
                else:
                    # Información básica de TCP
                    packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} [Flags: {packet_info['tcp_flags']}]"

            # Análisis de UDP
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['source_port'] = packet[UDP].sport  # Puerto origen
                packet_info['dest_port'] = packet[UDP].dport    # Puerto destino
                packet_info['udp_checksum'] = packet[UDP].chksum  # Suma de verificación UDP
                
                # Análisis de DNS sobre UDP
                if (packet[UDP].sport == 53 or packet[UDP].dport == 53) and packet.haslayer(DNS):
                    packet_info['protocol'] = 'DNS'
                    dns = packet[DNS]
                    packet_info['dns_id'] = dns.id  # ID de la consulta DNS
                    packet_info['dns_qr'] = 'Response' if dns.qr else 'Query'  # Tipo de mensaje DNS
                    packet_info['dns_opcode'] = dns.opcode  # Código de operación
                    packet_info['dns_rcode'] = dns.rcode    # Código de respuesta
                    
                    # Procesamiento de consultas DNS
                    if dns.qr == 0:  # Consulta
                        if dns.qd:
                            qname = dns.qd.qname.decode('utf-8')
                            qtype = dns.qd.qtype
                            packet_info['info'] = f"DNS Query: {qname} (Type: {qtype})"
                    else:  # Respuesta
                        answers = []
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            if hasattr(rr, 'rdata'):
                                answers.append(str(rr.rdata))
                        packet_info['info'] = f"DNS Response: {', '.join(answers)}"
                
                # Análisis de DHCP
                elif (packet[UDP].sport in [67, 68] or packet[UDP].dport in [67, 68]) and packet.haslayer(BOOTP):
                    packet_info['protocol'] = 'DHCP'
                    dhcp = packet[BOOTP]
                    packet_info['dhcp_message_type'] = dhcp.op  # Tipo de mensaje DHCP
                    packet_info['client_mac'] = dhcp.chaddr     # Dirección MAC del cliente
                    
                    # Análisis de opciones DHCP
                    if packet.haslayer(DHCP):
                        dhcp_options = packet[DHCP].options
                        message_type = next((opt[1] for opt in dhcp_options if opt[0] == 'message-type'), None)
                        requested_addr = next((opt[1] for opt in dhcp_options if opt[0] == 'requested_addr'), None)
                        packet_info['info'] = f"DHCP {['Discover', 'Offer', 'Request', 'ACK'][message_type-1] if message_type else 'Unknown'}"
                        if requested_addr:
                            packet_info['info'] += f" - Requested IP: {requested_addr}"
                
                # Análisis de protocolos de texto claro sobre UDP
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
                    # Información básica de UDP
                    src_port_name = udp_ports_dict.get(packet[UDP].sport, str(packet[UDP].sport))
                    dst_port_name = udp_ports_dict.get(packet[UDP].dport, str(packet[UDP].dport))
                    packet_info['info'] = f"{src_port_name} → {dst_port_name}"

            # Análisis de ICMPv4
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMPv4'
                icmp_type = packet[ICMP].type  # Tipo de mensaje ICMP
                icmp_code = packet[ICMP].code  # Código del mensaje
                packet_info['icmp_type'] = icmp_type
                packet_info['icmp_code'] = icmp_code
                packet_info['icmp_checksum'] = packet[ICMP].chksum  # Suma de verificación ICMP

                # Interpretación del mensaje ICMP
                if icmp_type in icmpv4_dict:
                    type_info = icmpv4_dict[icmp_type]['name']
                    code_info = icmpv4_dict[icmp_type]['codes'].get(icmp_code, 'Unknown Code')
                    packet_info['info'] = f"Type: {type_info}, Code: {code_info}"
                else:
                    packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"

        # Análisis de IPv6
        elif IPv6 in packet:
            packet_info['protocol'] = 'IPv6'
            packet_info['source'] = packet[IPv6].src  # Dirección IPv6 origen
            packet_info['destination'] = packet[IPv6].dst  # Dirección IPv6 destino
            packet_info['traffic_class'] = packet[IPv6].tc  # Clase de tráfico
            packet_info['flow_label'] = packet[IPv6].fl     # Etiqueta de flujo

            # Análisis de ICMPv6
            if any(layer in packet for layer in [ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA]):
                packet_info['protocol'] = 'ICMPv6'
                # Obtiene la capa ICMPv6
                icmpv6_layer = next(layer for layer in [ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA] if layer in packet)
                icmp_type = packet[icmpv6_layer].type  # Tipo de mensaje ICMPv6
                icmp_code = packet[icmpv6_layer].code  # Código del mensaje
                packet_info['icmp_type'] = icmp_type
                packet_info['icmp_code'] = icmp_code
                packet_info['icmp_checksum'] = packet[icmpv6_layer].cksum  # Suma de verificación ICMPv6

                # Interpretación del mensaje ICMPv6
                if icmp_type in icmpv6_dict:
                    type_info = icmpv6_dict[icmp_type]['name']
                    code_info = icmpv6_dict[icmp_type]['codes'].get(icmp_code, 'Unknown Code')
                    packet_info['info'] = f"Type: {type_info}, Code: {code_info}"
                else:
                    packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"

        return packet_info

    def _get_tcp_flags(self, flags):
        """Convierte las banderas TCP a un formato legible.
        Args:
            flags: Banderas TCP en formato raw
        Returns:
            str: Cadena con las banderas en formato legible"""
        return ' '.join([tcp_flags_dict.get(f, f) for f in str(flags)])

    def get_unique_packet(self, index):
        """Obtiene un paquete específico de la colección de paquetes únicos por protocolo.
        Args:
            index: Índice del paquete a recuperar
        Returns:
            dict: Información del paquete si existe, None en caso contrario"""
        packets_list = list(self.protocol_packets.values())
        try:
            return packets_list[index]
        except IndexError:
            return None

    def get_packet(self, index):
        """Obtiene un paquete específico por su índice.
        Args:
            index: Índice del paquete a recuperar
        Returns:
            dict: Información del paquete si existe, None en caso contrario"""
        if 0 <= index < len(self.packets):
            return self.analyze_packet(self.packets[index])
        return None

    def get_packet_count(self):
        """Retorna el número total de paquetes capturados en la sesión actual.
        Returns:
            int: Número total de paquetes capturados"""
        return len(self.packets)