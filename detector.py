import pyshark
from collections import Counter

malicious = pyshark.FileCapture('tcpdump/tcpdump.pcap')

malicious.load_packets()

tcp_streams = {}
packet_sizes = {}
stream_duration = {}
stream_regularity = {}

# Only want the TCP packets
for packet in malicious:
    if hasattr(packet, 'tcp'):
        # Organises each packet into its TCP stream
        if packet.tcp.stream not in tcp_streams:
            tcp_streams[packet.tcp.stream] = []
        if packet.tcp.stream not in packet_sizes:
            packet_sizes[packet.tcp.stream] = []
        # if packet.tcp.stream not in stream_duration:
        #    stream_duration[packet.tcp.stream] = []
        # if packet.tcp.stream not in stream_regularity:
        #    stream_regularity[packet.tcp.stream] = []

        tcp_streams[packet.tcp.stream].append(packet)
        packet_sizes[packet.tcp.stream].append(packet.tcp.len)

# Prints the number of packets in each stream
# Prints the packet size distributions of each stream
for key in tcp_streams:
    print("TCP STREAM: " + str(key))
    print("No. of Packets: " + str(len(tcp_streams[key])))
    print(Counter(packet_sizes[key][0]))

    print("ADASDASDASD" + str(tcp_streams[key].sniff_time))

    print()

malicious.close()


import matplotlib.pyplot as plt
import numpy as np

x = [key for key in tcp_streams]
y = [len(tcp_streams[key]) for key in tcp_streams]


fig, ax = plt.subplots()  # Create a figure containing a single axes.

ax.plot(x, y, 'bo')

plt.show()