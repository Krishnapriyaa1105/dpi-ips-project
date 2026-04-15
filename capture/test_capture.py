from scapy.all import sniff, wrpcap

print("Capturing 5 packets on your real network interface...")

def packet_callback(pkt):
    if pkt.haslayer('IP'):
        src = pkt['IP'].src
        dst = pkt['IP'].dst
        proto = pkt['IP'].proto
        print(f"{src} -> {dst} | Protocol: {proto}")
    if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
        print(f"Ports: {pkt.sport} -> {pkt.dport}")
    if pkt.haslayer('Raw'):
        print(f"Payload: {pkt['Raw'].load[:50]}...")  # first 50 bytes

# Sniff packets and print details
packets = sniff(count=5, prn=packet_callback)

# Save all captured packets to a .pcap file
wrpcap("dec9_capture.pcap", packets)
print("Packets saved to dec9_capture.pcap")
