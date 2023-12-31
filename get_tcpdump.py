import sys
import subprocess
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

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 get_tcpdump.py <number>")
        sys.exit(1)

    number = sys.argv[1]
    vms = ['ns0v4only', 'ns0v6only', 'ns0dualstack']
    file_types = ['v4only', 'v6only', 'dstack']

    for vm, file_type in zip(vms, file_types):
        scp_command = f"scp {vm}:~/{file_type}-{number}.pcap tcpdump-data/{file_type}-{number}.pcap"
        subprocess.run(scp_command, shell=True)

        pcap_file = f"tcpdump-data/{file_type}-{number}.pcap"
        extract_dns_info(pcap_file)

if __name__ == "__main__":
    main()

