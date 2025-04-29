# Diccionarios para interpretación de protocolos

# Diccionario para tipos y códigos ICMPv4
icmpv4_dict = {
    0: {"name": "Echo Reply", "codes": {0: "No Code"}},
    3: {
        "name": "Destination Unreachable",
        "codes": {
            0: "Net Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation Needed and Don't Fragment was Set",
            5: "Source Route Failed",
            6: "Destination Network Unknown",
            7: "Destination Host Unknown",
            8: "Source Host Isolated",
            9: "Communication with Destination Network is Administratively Prohibited",
            10: "Communication with Destination Host is Administratively Prohibited",
            11: "Destination Network Unreachable for Type of Service",
            12: "Destination Host Unreachable for Type of Service",
            13: "Communication Administratively Prohibited",
            14: "Host Precedence Violation",
            15: "Precedence cutoff in effect"
        }
    },
    4: {"name": "Source Quench", "codes": {0: "No Code"}},
    5: {
        "name": "Redirect",
        "codes": {
            0: "Redirect Datagram for the Network",
            1: "Redirect Datagram for the Host",
            2: "Redirect Datagram for the Type of Service and Network",
            3: "Redirect Datagram for the Type of Service and Host"
        }
    },
    8: {"name": "Echo", "codes": {0: "No Code"}},
    11: {
        "name": "Time Exceeded",
        "codes": {
            0: "Time to Live exceeded in Transit",
            1: "Fragment Reassembly Time Exceeded"
        }
    }
}

# Diccionario para tipos y códigos ICMPv6
icmpv6_dict = {
    1: {
        "name": "Destination Unreachable",
        "codes": {
            0: "No route to destination",
            1: "Communication with destination administratively prohibited",
            2: "Beyond scope of source address",
            3: "Address unreachable",
            4: "Port unreachable",
            5: "Source address failed ingress/egress policy",
            6: "Reject route to destination"
        }
    },
    2: {"name": "Packet Too Big", "codes": {0: "No Code"}},
    3: {
        "name": "Time Exceeded",
        "codes": {
            0: "Hop limit exceeded in transit",
            1: "Fragment reassembly time exceeded"
        }
    },
    4: {
        "name": "Parameter Problem",
        "codes": {
            0: "Erroneous header field encountered",
            1: "Unrecognized Next Header type encountered",
            2: "Unrecognized IPv6 option encountered"
        }
    },
    128: {"name": "Echo Request", "codes": {0: "No Code"}},
    129: {"name": "Echo Reply", "codes": {0: "No Code"}}
}

# Diccionario para flags TCP
tcp_flags_dict = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR'
}

# Diccionario para puertos UDP comunes
udp_ports_dict = {
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    161: "SNMP",
    162: "SNMP Trap",
    500: "IKE",
    514: "Syslog",
    520: "RIP",
    1900: "SSDP",
    5353: "mDNS"
}