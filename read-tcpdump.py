from scapy.all import rdpcap, DNS, DNSQR, IP

def extract_dns_info(pcap_file):
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(IP):
            dns = packet[DNS]
            ip = packet[IP]
            if dns.qr == 0 and ip.dport == 53:  # DNS query to port 53
                query_name = dns[DNSQR].qname.decode('utf-8')
                src_ip = ip.src
                print(f"Queried Domain: {query_name}, Source IP: {src_ip}")

# Replace 'your_pcap_file.pcap' with the path to your pcap file
extract_dns_info('tcpdump-data/v4only-pcap-2023-12-19T14:57:30+0000.pcap')

