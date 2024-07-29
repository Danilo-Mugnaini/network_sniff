from scapy.all import sniff, Raw, hexdump, conf, L3RawSocket

def packet_callback(packet):
    print(f"Packet: {packet.summary()}")
    if Raw in packet:
        print(f"Raw data: {packet[Raw].load}")
        hexdump(packet[Raw].load)

def start_sniffing(interface=None):
    print("Starting packet capture...")
    sniff(iface=interface, prn=packet_callback, store=False)

# Set Scapy to use L3RawSocket for Layer 3 sniffing
conf.L3socket = L3RawSocket

# Replace 'Wi-Fi' with the appropriate interface name for your system
start_sniffing("Wi-Fi")
