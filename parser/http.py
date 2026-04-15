from scapy.layers.http import HTTPRequest, HTTPResponse

def parse_http(packet):
    if packet.haslayer(HTTPRequest):
        return {
            "type": "http_request",
            "host": packet[HTTPRequest].Host,
            "path": packet[HTTPRequest].Path,
            "method": packet[HTTPRequest].Method.decode()
        }

    if packet.haslayer(HTTPResponse):
        return {
            "type": "http_response",
            "status": packet[HTTPResponse].Status_Code
        }

    return None
