# Diccionarios para interpretación de protocolos
# Este archivo contiene diccionarios que mapean códigos y tipos de diferentes protocolos
# de red a sus descripciones correspondientes

# Diccionario para tipos y códigos ICMPv4
# Mapea los tipos de mensajes ICMP versión 4 y sus códigos específicos
# Cada tipo tiene un nombre descriptivo y puede tener múltiples códigos
icmpv4_dict = {
    0: {"name": "Echo Reply", "codes": {0: "No Code"}},  # Respuesta de eco (ping reply)
    3: {
        "name": "Destination Unreachable",  # Destino inalcanzable
        "codes": {
            0: "Net Unreachable",  # Red inalcanzable
            1: "Host Unreachable",  # Host inalcanzable
            2: "Protocol Unreachable",  # Protocolo inalcanzable
            3: "Port Unreachable",  # Puerto inalcanzable
            4: "Fragmentation Needed and Don't Fragment was Set",  # Fragmentación necesaria pero DF activado
            5: "Source Route Failed",  # Fallo en la ruta de origen
            6: "Destination Network Unknown",  # Red de destino desconocida
            7: "Destination Host Unknown",  # Host de destino desconocido
            8: "Source Host Isolated",  # Host de origen aislado
            9: "Communication with Destination Network is Administratively Prohibited",  # Comunicación con red prohibida
            10: "Communication with Destination Host is Administratively Prohibited",  # Comunicación con host prohibida
            11: "Destination Network Unreachable for Type of Service",  # Red inalcanzable por tipo de servicio
            12: "Destination Host Unreachable for Type of Service",  # Host inalcanzable por tipo de servicio
            13: "Communication Administratively Prohibited",  # Comunicación prohibida administrativamente
            14: "Host Precedence Violation",  # Violación de precedencia de host
            15: "Precedence cutoff in effect"  # Corte de precedencia en efecto
        }
    },
    4: {"name": "Source Quench", "codes": {0: "No Code"}},  # Disminución de velocidad de origen
    5: {
        "name": "Redirect",  # Redirección
        "codes": {
            0: "Redirect Datagram for the Network",  # Redirección de datagrama para la red
            1: "Redirect Datagram for the Host",  # Redirección de datagrama para el host
            2: "Redirect Datagram for the Type of Service and Network",  # Redirección por tipo de servicio y red
            3: "Redirect Datagram for the Type of Service and Host"  # Redirección por tipo de servicio y host
        }
    },
    8: {"name": "Echo", "codes": {0: "No Code"}},  # Solicitud de eco (ping request)
    11: {
        "name": "Time Exceeded",  # Tiempo excedido
        "codes": {
            0: "Time to Live exceeded in Transit",  # TTL excedido en tránsito
            1: "Fragment Reassembly Time Exceeded"  # Tiempo de reensamblaje de fragmentos excedido
        }
    }
}

# Diccionario para tipos y códigos ICMPv6
# Mapea los tipos de mensajes ICMP versión 6 y sus códigos específicos
# Similar a ICMPv4 pero con códigos específicos para IPv6
icmpv6_dict = {
    1: {
        "name": "Destination Unreachable",  # Destino inalcanzable
        "codes": {
            0: "No route to destination",  # Sin ruta al destino
            1: "Communication with destination administratively prohibited",  # Comunicación prohibida
            2: "Beyond scope of source address",  # Fuera del alcance de la dirección de origen
            3: "Address unreachable",  # Dirección inalcanzable
            4: "Port unreachable",  # Puerto inalcanzable
            5: "Source address failed ingress/egress policy",  # Fallo en política de entrada/salida
            6: "Reject route to destination"  # Ruta rechazada al destino
        }
    },
    2: {"name": "Packet Too Big", "codes": {0: "No Code"}},  # Paquete demasiado grande
    3: {
        "name": "Time Exceeded",  # Tiempo excedido
        "codes": {
            0: "Hop limit exceeded in transit",  # Límite de saltos excedido en tránsito
            1: "Fragment reassembly time exceeded"  # Tiempo de reensamblaje de fragmentos excedido
        }
    },
    4: {
        "name": "Parameter Problem",  # Problema de parámetros
        "codes": {
            0: "Erroneous header field encountered",  # Campo de cabecera erróneo encontrado
            1: "Unrecognized Next Header type encountered",  # Tipo de siguiente cabecera no reconocido
            2: "Unrecognized IPv6 option encountered"  # Opción IPv6 no reconocida
        }
    },
    128: {"name": "Echo Request", "codes": {0: "No Code"}},  # Solicitud de eco
    129: {"name": "Echo Reply", "codes": {0: "No Code"}}  # Respuesta de eco
}

# Diccionario para flags TCP
# Mapea las banderas TCP a sus nombres completos
tcp_flags_dict = {
    'F': 'FIN',  # Finalizar conexión
    'S': 'SYN',  # Sincronizar números de secuencia
    'R': 'RST',  # Reiniciar la conexión
    'P': 'PSH',  # Función Push
    'A': 'ACK',  # Confirmación
    'U': 'URG',  # Urgente
    'E': 'ECE',  # Notificación de congestión ECN-Echo
    'C': 'CWR'   # Ventana de congestión reducida
}

# Diccionario para puertos UDP comunes
# Mapea números de puerto UDP a servicios comunes
udp_ports_dict = {
    53: "DNS",               # Sistema de nombres de dominio
    67: "DHCP Server",       # Servidor DHCP
    68: "DHCP Client",       # Cliente DHCP
    69: "TFTP",             # Protocolo de transferencia de archivos trivial
    123: "NTP",             # Protocolo de tiempo de red
    137: "NetBIOS Name Service",    # Servicio de nombres NetBIOS
    138: "NetBIOS Datagram Service",  # Servicio de datagramas NetBIOS
    139: "NetBIOS Session Service",   # Servicio de sesión NetBIOS
    161: "SNMP",            # Protocolo simple de administración de red
    162: "SNMP Trap",       # Trampas SNMP
    500: "IKE",             # Intercambio de claves de Internet
    514: "Syslog",          # Registro del sistema
    520: "RIP",             # Protocolo de información de enrutamiento
    1900: "SSDP",           # Protocolo simple de descubrimiento de servicios
    5353: "mDNS"           # DNS multicast
}