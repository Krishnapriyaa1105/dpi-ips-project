from scapy.layers.tls.all import TLSClientHello


def parse_tls(packet):

    if packet.haslayer(TLSClientHello):

        try:
            sni = packet[TLSClientHello].servernames[0].servername.decode()

            return {
                "type": "tls",
                "domain": sni
            }

        except:
            return {
                "type": "tls",
                "info": "Encrypted TLS traffic"
            }

    return None