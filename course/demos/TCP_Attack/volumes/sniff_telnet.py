#! /usr/bin/env python3

# Sniff Telnet Packets

from scapy.all import IP, TCP, sniff


def telnet_sniffer(packet):
    # Check if the packet is a Telnet packet
    # if packet.haslayer(TCP):
    # Print the packet
    print(f'src={packet[IP].src} dst={packet[IP].dst} \
          src={packet[TCP].sport} dst={packet[TCP].dport} \
            seq={packet[TCP].seq} ack={packet[TCP].ack} \
          flags={packet[TCP].flags}')


if __name__ == "__main__":
    # Sniff Telnet packets
    # find the interface name by running ifconfig;
    # pick the one with docker-compose network settings
    sniff(iface="br-37b8bb83ca93", filter="tcp and dst port 23", prn=telnet_sniffer)
    # Usage: python3 sniff_telnet.py
    # Example: python3 sniff_telnet.py
