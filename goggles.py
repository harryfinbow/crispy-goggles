import sys
import pyshark
import pandas
#sys.stdout.write("\033[F")

def capture_live_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface)
    for raw_packet in capture.sniff_continuously():
        print(filter_tcp_traffic(raw_packet))

def read_capture_file(file_path):
    tcp_packets_by_index = {}
    tcp_streams_by_ip = {} #{'172.1.1.1/172.1.1.2': [tcp_streams[1], tcp_streams[2]]} THIS NEEDS TO BE A DATAFRAME
    tcp_streams_statistics = {} #'172.1.1.1/172.1.1.2': {'Count', 'Min', 'Max', 'Mean', 'Standard Dev', 'Jitter', 'Skew'}}


    tcp_stream = pandas.DataFrame(columns = [])

    capture = pyshark.FileCapture(file_path, keep_packets=False)

    for raw_packet in capture:
        tcp_packet = filter_tcp_traffic(raw_packet)

        if tcp_packet is not None:
            tcp_streams = group_by_stream_index(tcp_packet, tcp_packets_by_index)
            tcp_streams_by_ip = group_tcp_streams_by_ip(tcp_packet, tcp_packets_by_index, tcp_streams_by_ip)
            tcp_streams_statistics = get_tcp_stream_statistics(tcp_packet, tcp_packets_by_index)

            print(tcp_streams_statistics)
            sys.stdout.write("\033[F")


def get_tcp_stream_statistics(packet, grouped_streams):
    ip_pair = packet['Source address'] + "/" + packet['Destination address']

    for stream in grouped_streams[ip_pair]:
        grouped_streams[ip_pair][stream]['Length']

    return grouped_streams[ip_pair][0]['Length']


def group_tcp_streams_by_ip(packet, streams, grouped_streams):
    ip_pair = packet['Source address'] + "/" + packet['Destination address']

    if packet[ip_pair, 'Stream index'] not in grouped_streams:

def old_group_tcp_streams_by_ip(packet, streams, grouped_streams):
    ip_pair = packet['Source address'] + "/" + packet['Destination address']

    if ip_pair not in grouped_streams:
        grouped_streams[ip_pair] = [streams[packet['Stream index']]]
    else:
        grouped_streams[ip_pair].append(streams[packet['Stream index']])

    return grouped_streams


def group_by_stream_index(packet, streams):
    """
    This function is groups all packets with the same stream index together.
    :param packet: tcp packet / streams: dictionary of previously grouped packets
    :return: dictionary of grouped packets
    """
    if packet['Stream index'] not in streams:
        streams[packet['Stream index']] = {'Source':       packet['Source address'], 
                                            'Destination': packet['Destination address'], 
                                            'Start time':  packet['Packet time'], 
                                            'Length':      packet['Packet length']}
    else:
        streams[packet['Stream index']]['Length'] =  streams[packet['Stream index']]['Length'] + packet['Packet length']

    return streams


def filter_tcp_traffic(packet):
    """
    This function is designed to parse all the Transmission Control Protocol(TCP) packets
    :param packet: raw packet
    :return: specific packet details
    """
    if hasattr(packet, 'tcp'):
       results = get_packet_details(packet)
       return results


def get_formatted_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time


    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {protocol}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}\n'


def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    stream_index = int(packet.tcp.stream)
    source_address = packet.ip.src
    destination_address = packet.ip.dst
    packet_time = packet.sniff_time
    packet_length = int(packet.length)

    #return pandas.DataFrame([(stream_index, source_address, destination_address, packet_time, packet_length)], columns=['Stream index', 'Source address', 'Destination address', 'Start time', 'Packet length'])

    #"""
    return {'Stream index': stream_index,
            'Source address' : source_address,
            'Destination address' : destination_address,
            'Packet time': packet_time,
            'Packet length': packet_length}
    #"""


def replace_ip_with_index(ip):
    global ip_index, ip_index_list, updated

    if ip not in ip_index_list:
        ip_index_list[ip] = ip_index
        index = ip_index
        ip_index = ip_index + 1
        updated = 1
    else:
        index = ip_index_list[ip]

    return index

#capture_live_packets('\\Device\\NPF_{25D9BFB1-5E09-4CC1-84E6-0CFCF3015D87}')
read_capture_file('tcpdump/10-5.pcap')