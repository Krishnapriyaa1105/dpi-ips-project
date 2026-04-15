from scapy.layers.dns import DNS, DNSQR

def parse_dns(packet):

    if packet.haslayer(DNS) and packet.getlayer(DNS).qd:

        query = packet[DNSQR].qname.decode()

        return {
            "type": "dns_query",
            "domain": query
        }

    return None