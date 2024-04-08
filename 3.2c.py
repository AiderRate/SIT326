from scapy.all import *
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from geoip2.database import Reader
from collections import Counter

def load_pcap(filename):
    #Load packets from pcap file.
    packets = []
    for packet in rdpcap(filename): #read the pcap file and get a list of packages 
        packets.append(packet) #adding pcap data to consoliidated array
    return packets

def sliding_window_analysis(packets, window_size):
    #Perform sliding window analysis.
    results = []
    for i in range(0, len(packets), window_size):
        window = packets[i:i+window_size]
        sent_count = len([p for p in window if p.haslayer(IP) and IP in p]) #total sent
        recv_count = len([p for p in window if p.haslayer(IP) and IP not in p]) #total recieved
        metric = (sent_count - recv_count) / window_size  # Normalize to [-1, 1]
        results.append(metric)
    return results

def plot_metrics(window_sizes, metrics):
    #Plot metrics across various sliding window sizes.
    for size, metric in zip(window_sizes, metrics):
        plt.plot(metric, label=f'Window Size: {size}')
    plt.xlabel('Window Index')
    plt.ylabel('Metric')
    plt.legend()
    plt.title('Traffic Pattern Analysis')
    plt.show()

def time_based_analysis(packets, time_interval):
    #Perform time-based packet analysis.
    start_time = packets[0].time
    end_time = packets[-1].time
    num_intervals = int((end_time - start_time) / time_interval) + 1
    intervals = [[] for _ in range(num_intervals)]
    
    for packet in packets:
        interval_index = int((packet.time - start_time) / time_interval)
        intervals[interval_index].append(packet)
    
    metrics = [sliding_window_analysis(interval, window_size=10) for interval in intervals]
    avg_metrics = [np.mean(m) for m in metrics]
    
    plt.plot(np.arange(len(avg_metrics)), avg_metrics)
    plt.xlabel('Time Interval')
    plt.ylabel('Average Metric')
    plt.title('Time-based Traffic Analysis')
    plt.show()

def ip_analysis(packets, reader):
    #Identify the source IPs of incoming packets and compile a list of the top ten originating countries.
    ip_counter = Counter()
    errors=[]
    for packet in packets:
        if packet.haslayer(IP) and IP in packet:
            src_ip = packet[IP].src
            try:
                match = reader.country(src_ip)
                if match.country.iso_code:
                    country = match.country.name
                    ip_counter[country] += 1
            except Exception as e:
                errors.append(e) #creates error list for every run
                pass
        #print(errors)#prints out all error notifications
    
    top_countries = ip_counter.most_common(10)
    df = pd.DataFrame(top_countries, columns=['Country', 'Packet Count'])
    print(df)

def ip_analysis2(packets):
    #Identify the source IPs of incoming packets and compile a list of the top ten originating IPs
    ip_counter = Counter()
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            ip_counter[src_ip] += 1
    
    top_ips = ip_counter.most_common(10)
    df = pd.DataFrame(top_ips, columns=['Source IP', 'Packet Count'])
    print(df)

def main():
    filename = 'malware.pcap'
    packets = load_pcap(filename)
    
    window_sizes = [50, 100, 150]  # Define different window sizes for analysis
    metrics = [sliding_window_analysis(packets, size) for size in window_sizes]
    plot_metrics(window_sizes, metrics)
    
    time_interval = 60  # seconds
    time_based_analysis(packets, time_interval)
    
    reader = Reader('GeoLite2-Country.mmdb')
    ip_analysis(packets, reader)
    print()
    ip_analysis2(packets)

if __name__ == "__main__":
    main()
