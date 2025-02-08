from scapy.all import *

# Define the network interface to sniff on (e.g., 'eth0' or 'wlan0')

iface = 'wlo1'

# Create a packet sniffer with filters

sniffer = sniff(iface=iface, 
                filter="tcp or udp or icmp", 
                count=50, 
                prn=lambda x: x.summary())

# Print the captured packets
for packet in sniffer:

    print(packet.show())
