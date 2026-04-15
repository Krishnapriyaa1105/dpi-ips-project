from scapy.all import sniff

iface = r"\Device\NPF_{9369B1A3-FB87-497F-BE6E-728A5496C5DA}"

def show(pkt):
    print(pkt.summary())

print("Capturing 5 packets on your real network interface...")
sniff(iface=iface, prn=show, count=5)
