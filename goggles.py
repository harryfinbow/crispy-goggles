import os
import time
import numpy
import pandas
import pyshark

from scipy import stats

start_time = time.time()

def print_every(rate, scores):
    if print_every.packets_read % rate == 0:
        current_time = time.time()
        statistics = display_statistics(print_every.packets_read, rate, current_time, print_every.last_print)

        print(statistics)
        print(scores.head(25))

        print_every.last_print = current_time
    print_every.packets_read += 1
print_every.packets_read = 0
print_every.last_print = time.time()


def display_statistics(packets_read, rate, time, last_print):
    os.system('cls' if os.name=='nt' else 'clear')
    return f'Packets Analysed:   {packets_read}' \
           f'\nTime Elapsed:       {time - start_time:.2f} seconds' \
           f'\nPackets per second: {rate / (time - last_print):.0f}'


def store(packet):
    source = packet['Source']
    destination = packet['Destination']
    index = packet['Stream index']

    if destination in tcp_streams_cache and source in tcp_streams_cache[destination] :
        if index not in tcp_streams_cache[destination][source]:
            tcp_streams_cache[destination][source][index] = [packet['Time'], 0, 0, 0, 0, 0]

        tcp_streams_cache[destination][source][index][1] = packet['Time']
        tcp_streams_cache[destination][source][index][2] += 1
        tcp_streams_cache[destination][source][index][3] += packet['Length']

    # Source and Destination flipped
    elif source in tcp_streams_cache and destination in tcp_streams_cache[source]:
        if index not in tcp_streams_cache[source][destination]:
            tcp_streams_cache[source][destination][index] = [packet['Time'], 0, 0, 0, 0, 0]

        tcp_streams_cache[source][destination][index][1] = packet['Time']
        tcp_streams_cache[source][destination][index][4] += 1
        tcp_streams_cache[source][destination][index][5] += packet['Length']

        return destination, source

    elif destination not in tcp_streams_cache:
        tcp_streams_cache[destination] = {source: {index: [packet['Time'], 0, 0, 0, 0, 0]}}

    else:
        tcp_streams_cache[destination][source] = {index: [packet['Time'], 0, 0, 0, 0, 0]}
    
    return source, destination


def retrieve_values(tcp_streams):
    values = { 'Outbound Length': [], 'Inbound Length': [], 'Periodicity': [], 'Duration': 0 }

    window = int(0.8 * len(tcp_streams))

    start_times = []
    for stream in list(tcp_streams.keys())[-window:]:
        start_times.append(tcp_streams[stream][0])
        values['Outbound Length'].append(tcp_streams[stream][3])
        values['Inbound Length'].append(tcp_streams[stream][5])
        #values['Outbound Packets'].append(tcp_streams[stream][2])
        #values['Inbound Packets'].append(tcp_streams[stream][4])

    values['Periodicity'] = numpy.diff(start_times)
    values['Duration'] = start_times[-1] - start_times[0]

    return values


def calculate_score(results, duration):
    timeSpreadScore = max(1 - (results['PeriodicitySpread'] / 30), 0) # Seconds
    outLengthSpreadScore = max(1 - (results['OutLengthSpread'] / 64), 0) # Bytes
    inLengthSpreadScore = max(1 - (results['InLengthSpread'] / 64), 0) # Bytes

    timeCountScore = min(results['Count'] / (duration / 60), 1) # DIVIDE STREAM COUNT BY NUMBER OF IPs How many there were vs how many there should have been given the time (e.g. 5 / (300/60) = 1)
    outLengthCharacteristicScore = max(1 - results['OutLengthMode'] / 65535, 0) # Bytes
    inLengthCharacteristicScore = max(1 - results['InLengthMode'] / 65535, 0) # Bytes

    scores = [timeSpreadScore, outLengthSpreadScore, inLengthSpreadScore, timeCountScore, outLengthCharacteristicScore, inLengthCharacteristicScore]
    score = sum(scores) / len(scores)
    score_breakdown = " + ".join(map('{:.2f}'.format, scores))

    return score, score_breakdown


def analyse(source, destination, tcp_streams):
    tcp_streams = tcp_streams_cache[destination][source]

    results = {'Source': source, 'Destination': destination, 'Count': len(tcp_streams),
               'PeriodicitySpread': 0, 'OutLengthSpread': 0, 'InLengthSpread': 0,
               'PeriodicityJitter': 0, 'OutLengthJitter': 0, 'InLengthJitter': 0,
                                       'OutLengthMode':   0, 'InLengthMode':   0}

    values = retrieve_values(tcp_streams)    

    results['PeriodicitySpread'] = stats.median_abs_deviation(values['Periodicity'])
    results['OutLengthSpread']   = stats.median_abs_deviation(values['Outbound Length'])
    results['InLengthSpread']    = stats.median_abs_deviation(values['Inbound Length'])

    results['PeriodicityJitter'] = numpy.std(values['Periodicity']) / numpy.mean(values['Periodicity'])
    results['OutLengthJitter']   = numpy.std(values['Outbound Length']) / numpy.mean(values['Outbound Length']) 
    results['InLengthJitter']    = numpy.std(values['Inbound Length']) / numpy.mean(values['Inbound Length'])

    results['OutLengthMode']   = stats.mode(values['Outbound Length'])[0][0]
    results['InLengthMode']    = stats.mode(values['Inbound Length'])[0][0]

    score, score_breakdown = calculate_score(results, values['Duration'])

    return [source, destination, len(tcp_streams),
            results['PeriodicitySpread'], results['PeriodicityJitter'], 
            results['OutLengthSpread'], results['OutLengthJitter'], 
            results['InLengthSpread'], results['InLengthJitter'], 
            score, score_breakdown]
    

def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    stream_index = int(getattr(packet, 'stream index'))
    source_address = packet.source
    destination_address = packet.destination
    packet_time = float(packet.time)
    packet_length = int(packet.length)
    
    return {'Stream index': stream_index,
            'Source':       source_address,
            'Destination':  destination_address,
            'Time':         packet_time,
            'Length':       packet_length}


tcp_streams_cache = {}
scores = pandas.DataFrame(columns = ['Stream count', 'pSpread', 'pJitter',  'oSpread', 'oJitter', 'iSpread', 'iJitter', 'Score', 'Score breakdown'])

capture = pyshark.FileCapture('tcpdump/30-seconds_0.20-jitter/01.pcap', keep_packets=False, only_summaries=True)

results = []
for packet in capture:
    if hasattr(packet, 'protocol'):
        if packet.protocol == 'TCP':
            tcp_packet = get_packet_details(packet)
            source, destination = store(tcp_packet)

            if len(tcp_streams_cache[destination][source]) % 10 == 0 and len(tcp_streams_cache[destination][source]) > 0:
                results = analyse(source, destination, tcp_streams_cache)
                scores.loc[str(results[0]) + '/' + str(results[1])] = results[2:]
                scores.sort_values(by='Score', ascending=False, inplace=True)
        
            
    print_every(10000, scores)