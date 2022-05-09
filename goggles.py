import os
import time
import numpy
import pandas
import pyshark
from scipy import stats

pandas.set_option('display.max_rows', 500)
pandas.set_option('display.max_columns', 500)
pandas.set_option('display.width', 150)

START_TIME = time.time()
MINIMUM_STREAM_COUNT = 10
PACKETS_SINCE_LAST_UPDATE = 1000


def filter_packet(packet):
    if not hasattr(packet, 'tcp'):
        return

    return get_packet_details(packet)

    
def get_packet_details(packet):
    packet_details = {'Stream index': int(packet.tcp.stream),
                      'Source':       str(packet.ip.src),
                      'Destination':  str(packet.ip.dst),
                      'Time':         float(packet.frame_info.time_relative),
                      'Length':       int(packet.frame_info.len)}
    return packet_details


def process_packet(packet):
    source      = packet['Source']
    destination = packet['Destination']
    index       = packet['Stream index']

    # Outbound packets
    if destination in tcp_streams_cache and source in tcp_streams_cache[destination] :
        if index not in tcp_streams_cache[destination][source]:
            tcp_streams_cache[destination][source][index] = [packet['Time'], 0, 0, 0, 0, 0]

        tcp_streams_cache[destination][source][index][1] = packet['Time']
        tcp_streams_cache[destination][source][index][2] += 1
        tcp_streams_cache[destination][source][index][3] += packet['Length']

    #  Inbound packets (Source and Destination flipped)
    elif source in tcp_streams_cache and destination in tcp_streams_cache[source]:
        if index not in tcp_streams_cache[source][destination]:
            tcp_streams_cache[source][destination][index] = [packet['Time'], 0, 0, 0, 0, 0]

        tcp_streams_cache[source][destination][index][1] = packet['Time']
        tcp_streams_cache[source][destination][index][4] += 1
        tcp_streams_cache[source][destination][index][5] += packet['Length']

        return {'Source': destination, 'Destination': source}

    # New Destination address
    elif destination not in tcp_streams_cache:
        tcp_streams_cache[destination] = {source: {index: [packet['Time'], 0, 0, 0, 0, 0]}}

    # New Source address
    else:
        tcp_streams_cache[destination][source] = {index: [packet['Time'], 0, 0, 0, 0, 0]}
    
    return {'Source': source, 'Destination': destination}


def analyse_packet(packet):
    source = packet['Source']
    destination = packet['Destination']

    tcp_streams = tcp_streams_cache[destination][source]

    if len(tcp_streams) < MINIMUM_STREAM_COUNT:
        return 0

    results = {'Source': source, 'Destination': destination, 'Count': len(tcp_streams),
               'PeriodicitySpread': 0, 'OutLengthSpread': 0, 'InLengthSpread': 0,
               'PeriodicityJitter': 0, 'OutLengthJitter': 0, 'InLengthJitter': 0,
               'PeriodicitySkew'  : 0, 'OutLengthSkew'  : 0, 'InLengthSkew'  : 0,
                                       'OutLengthMode'  : 0, 'InLengthMode'  : 0}

    values = retrieve_values(tcp_streams)
    
    results['PeriodicityJitter'] = (max(values['Periodicity'][1:]) - numpy.mean(values['Periodicity'][1:])) / numpy.mean(values['Periodicity'][1:])
    results['OutLengthJitter']   = (max(values['Outbound Length']) - numpy.mean(values['Outbound Length'])) / numpy.mean(values['Outbound Length']) 
    results['InLengthJitter']    = (max(values['Inbound Length']) - numpy.mean(values['Inbound Length'])) / numpy.mean(values['Inbound Length'])

    # Check IP pair within maximum / minimum jitter bounds
    if results['PeriodicityJitter'] > 10  or results['PeriodicityJitter'] < 0.1 or results['OutLengthJitter'] > 5: 
        tcp_streams_cache[destination].pop(source)
        return 0


    results['PeriodicitySpread'] = stats.median_abs_deviation(values['Periodicity'][1:])
    results['OutLengthSpread']   = stats.median_abs_deviation(values['Outbound Length'][:-1])
    results['InLengthSpread']    = stats.median_abs_deviation(values['Inbound Length'][:-1])

    results['PeriodicitySkew'] = bowleySkew(values['Periodicity'][1:])
    results['OutLengthSkew']   = bowleySkew(values['Outbound Length'][:-1])
    results['InLengthSkew']    = bowleySkew(values['Inbound Length'][:-1])

    results['OutLengthMode']     = stats.mode(values['Outbound Length'])[0][0]
    results['InLengthMode']      = stats.mode(values['Inbound Length'])[0][0]

    malicious = 1 if destination == '172.18.0.2' else 0
    score, score_breakdown = calculate_score(results, values['Duration'])

    return [source, destination, len(tcp_streams),
            results['PeriodicitySpread'], results['PeriodicityJitter'], results['PeriodicitySkew'],
            results['OutLengthSpread'], results['OutLengthJitter'], results['InLengthSpread'],
            malicious, score, score_breakdown]


def retrieve_values(tcp_streams):
    values = { 'Outbound Length': [], 'Inbound Length': [], 'Periodicity': [], 'Duration': 0 }

    start_times = []
    for stream in list(tcp_streams.keys()):

        start_times.append(tcp_streams[stream][0])
        values['Outbound Length'].append(tcp_streams[stream][3])
        values['Inbound Length'].append(tcp_streams[stream][5])

    values['Periodicity'] = numpy.diff(start_times)
    values['Duration'] = start_times[-1] - start_times[0]

    return values


def bowleySkew(attribute):
    attribute = sorted(attribute)

    low =  attribute[round(0.25*len(attribute)) - 1]
    high = attribute[round(0.75*len(attribute)) - 1]
    mid =  attribute[round(0.50*len(attribute)) - 1]

    if high - low != 0 and mid != low and mid != high:
        return (low + high - 2*mid) / (mid - low)

    else:
        return 0


def calculate_score(results, duration):
    timeSpreadScore = max(1 - (results['PeriodicitySpread'] / 30), 0) # Seconds
    outLengthSpreadScore = max(1 - (results['OutLengthSpread'] / 64), 0) # Bytes
    inLengthSpreadScore = max(1 - (results['InLengthSpread'] / 64), 0) # Bytes

    timeSkewScore = max(1 - abs(results['PeriodicitySkew']), 0) # Seconds

    timeCountScore = min(results['Count'] / (duration / 60), 1) # DIVIDE STREAM COUNT BY NUMBER OF IPs How many there were vs how many there should have been given the time (e.g. 5 / (300/60) = 1)
    outLengthCharacteristicScore = max(1 - results['OutLengthMode'] / 65535, 0) # Bytes
    inLengthCharacteristicScore = max(1 - results['InLengthMode'] / 65535, 0) # Bytes

    scores = [timeSpreadScore, timeSkewScore, outLengthSpreadScore, inLengthSpreadScore, timeCountScore, outLengthCharacteristicScore, inLengthCharacteristicScore]
    score = sum(scores) / len(scores)
    score_breakdown = " + ".join(map('{:.2f}'.format, scores))

    return score, score_breakdown


def print_every(rate, scores):
    if print_every.packets_read % rate == 0:
        current_time = time.time()
        statistics = display_statistics(print_every.packets_read, rate, current_time, print_every.last_print)

        print(statistics)

        if scores.empty:
            print("Not enough streams")
        else:
            print(scores[['Stream count', 'pSpread', 'pJitter',  'pSkew', 'oSpread', 'oJitter', 'iSpread', 'Malicious', 'Score']].head(25))
        

        print_every.last_print = current_time
    print_every.packets_read += 1
print_every.packets_read = 0
print_every.last_print = time.time()


def display_statistics(packets_read, rate, time, last_print):
    os.system('cls' if os.name=='nt' else 'clear')

    return f'Packets Analysed:   {packets_read}' \
           f'\nTime Elapsed:       {time - START_TIME:.2f} seconds' \
           f'\nPackets per second: {rate / (time - last_print):.0f}'


# Global storage for grouped streams and scores table
tcp_streams_cache = {}
scores = pandas.DataFrame(columns = ['Stream count', 'pSpread', 'pJitter',  'pSkew', 'oSpread', 'oJitter', 'iSpread', 'Malicious', 'Score', 'Score breakdown'])

if __name__ == '__main__':
    capture = pyshark.LiveCapture(interface='botnet', output_file="/tcpdump/tcpdump")
    #capture = pyshark.FileCapture('tcpdump/tcpdump.pcap')

    for packet in capture:
        filtered_packet  = filter_packet(packet)
        if filtered_packet:
            processed_packet = process_packet(filtered_packet)
            analysed_packet  = analyse_packet(processed_packet)

            if analysed_packet:
                scores.loc[str(analysed_packet[0]) + '/' + str(analysed_packet[1])] = analysed_packet[2:]
                scores.sort_values(by='Score', ascending=False, inplace=True)

            print_every(PACKETS_SINCE_LAST_UPDATE, scores)

    print_every(1, scores)
