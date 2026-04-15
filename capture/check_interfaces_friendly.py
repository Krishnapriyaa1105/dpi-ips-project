from scapy.all import get_if_list, get_if_addr

print("Interfaces with IP addresses:")
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        print(f"{iface}   -->   {ip}")
    except:
        pass
