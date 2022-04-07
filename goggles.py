import os
import re
import time
import pyshark
import pandas

start_time = time.time()
malicious_ip = re.compile(r'172.18.0.(\d)*/172.18.0.(\d)*')

def cls():
    os.system('cls' if os.name=='nt' else 'clear')

def print_every(x, obj):    
    if not print_every.counter % x:
        current_time = time.time()
        cls()
        print('Packets Analysed:', print_every.counter)
        print("Time Elapsed:     %s seconds" % (current_time - start_time))
        print("Time per 1000:    %s seconds" % (current_time - print_every.last_time))
        print(obj)

        print_every.last_time = current_time

    print_every.counter += 1
print_every.counter = 0
print_every.last_time = 0


def capture_live_packets(network_interface):
    tcp_streams = {}
    tcp_streams_statistics = pandas.DataFrame(columns = ['Stream count', 'Periodicity jitter', 'Periodicity skew', 'Duration jitter', 'Duration skew', 'Length jitter', 'Length skew'])

    capture = pyshark.LiveCapture(interface=network_interface, only_summaries = True)
    
    for raw_packet in capture.sniff_continuously():
        print(filter_tcp_traffic(raw_packet))

        print_every(1000, 0)
    

def read_capture_file(file_path):
    tcp_streams = {}
    tcp_streams_statistics = pandas.DataFrame(columns = ['Stream count', 'Periodicity jitter', 'Periodicity skew', 'Duration jitter', 'Duration skew', 'Length jitter', 'Length skew', 'Malicious'])

    capture = pyshark.FileCapture(file_path, keep_packets=False, only_summaries=True)

    #'''
    for raw_packet in capture:
        tcp_packet = filter_tcp_traffic(raw_packet)

        if tcp_packet is not None:
            tcp_streams = group_tcp_streams_by_ip(tcp_packet, tcp_streams)
            tcp_streams_statistics = get_tcp_streams_statistics(tcp_packet, tcp_streams, tcp_streams_statistics)

            print_every(1000, tcp_streams_statistics)
    '''

    for raw_packet in capture:
       # filter_tcp_traffic(raw_packet)

        print_every(1000, 0)
    '''


def group_tcp_streams_by_ip(packet, tcp_streams):
    tcp_stream = pandas.DataFrame([(packet['Stream index'], packet['Time'], packet['Length'], 0)], columns = ['Stream index', 'Time', 'Length', 'Duration'])
    
    if packet['IP pair'] not in tcp_streams:
        tcp_streams[packet['IP pair']] = tcp_stream

    elif packet['Stream index'] not in tcp_streams[packet['IP pair']]['Stream index'].values:
        tcp_streams[packet['IP pair']] = pandas.concat([tcp_streams[packet['IP pair']], tcp_stream])

    else:
        tcp_streams[packet['IP pair']]['Length'] = tcp_streams[packet['IP pair']]['Length'] + packet['Length']
        tcp_streams[packet['IP pair']]['Duration'] = packet['Time'] - tcp_streams[packet['IP pair']]['Time']

    return tcp_streams


def get_tcp_streams_statistics(packet, tcp_streams, tcp_streams_statistics):
    stream_count = len(tcp_streams[packet['IP pair']].index)

    if stream_count > 10:
        periodicity_jitter = (tcp_streams[packet['IP pair']]['Time'].std() / tcp_streams[packet['IP pair']]['Time'].mean()) * 100
        periodicity_skew = tcp_streams[packet['IP pair']]['Time'].skew()

        duration_jitter = (tcp_streams[packet['IP pair']]['Duration'].std() / tcp_streams[packet['IP pair']]['Duration'].mean()) * 100
        duration_skew = tcp_streams[packet['IP pair']]['Duration'].skew()

        length_jitter = (tcp_streams[packet['IP pair']]['Length'].std() / tcp_streams[packet['IP pair']]['Length'].mean()) * 100
        length_skew = tcp_streams[packet['IP pair']]['Length'].skew()

        malicious = 1 if bool(malicious_ip.search(packet['IP pair'])) else 0

        tcp_streams_statistics.loc[packet['IP pair']] = [stream_count, periodicity_jitter, periodicity_skew, duration_jitter, duration_skew, length_jitter, length_skew, malicious]

    return tcp_streams_statistics


def filter_tcp_traffic(packet):
    """
    This function is designed to parse all the Transmission Control Protocol(TCP) packets
    :param packet: raw packet
    :return: specific packet details
    """
    if hasattr(packet, 'protocol'):
       if packet.protocol == 'TCP':
            results = get_packet_details(packet)
            return results

def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    stream_index = int(getattr(packet, 'stream index'))
    source_address = packet.source
    destination_address = packet.destination
    ip_pair = source_address + "/" + destination_address
    packet_time = float(packet.time)
    packet_length = int(packet.length)
    

    return {'Stream index': stream_index,
            'Source address' : source_address,
            'Destination address' : destination_address,
            'IP pair': ip_pair,
            'Time': packet_time,
            'Length': packet_length}

#capture_live_packets('\\Device\\NPF_{25D9BFB1-5E09-4CC1-84E6-0CFCF3015D87}')
#capture_live_packets('\\Device\\NPF_{7409A38B-59FA-4DD0-BFA0-69D15666F1E6}')

read_capture_file('tcpdump/smaller-test.pcap')