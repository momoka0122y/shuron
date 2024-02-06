import json
import requests
import sys
import itertools
import subprocess
import os  # Add this line to import the os module
from scapy.all import rdpcap, DNS, DNSQR, IP, IPv6
import ast

def process_data(data, research_name):
    output = []
    for entry in data:
        prb_id = entry.get('prb_id')
        from_ip = entry.get('from')

        for resultset in entry.get('resultset', []):
            dst_addr = resultset.get('dst_addr')
            src_addr = resultset.get('src_addr')
            result = resultset.get('result', {})
            ancount = result.get('ANCOUNT', -1)
            ancount_status = '1' if ancount == 1 else '0'

            output.append({
                "Probe ID": prb_id,
                "From": from_ip,
                "Destination Addr": dst_addr,
                "Source Addr": src_addr,
                "ANCOUNT": ancount_status,
                "Research Name": research_name
            })
            if research_name == "v4only_v4only_AAAA" and ancount_status == '1':
                print("----------------------")
                print(' if "Research Name" == "v4only_v4only_AAAA":')
                print(prb_id)
                print(resultset)
                print("----------------------")

    return output

def get_ripe_data(measurement_ids):
    all_data = []
    domain_types = ['dstack', 'v4only', 'v6only']
    query_types = ['A', 'AAAA']
    i=0
    for domain_pair in itertools.product(domain_types, repeat=2):
        for query_type in query_types:
            current_id = measurement_ids[i]
            i+=1
            research_name = f"{domain_pair[0]}_{domain_pair[1]}_{query_type}"
            url = f"https://atlas.ripe.net/api/v2/measurements/{current_id}/results/"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                all_data.extend(process_data(data, research_name))
            else:
                print(f"Failed to retrieve data for {research_name}")

    return all_data


def extract_dns_info(pcap_file):
    output = []
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and (packet.haslayer(IP) or packet.haslayer(IPv6)):
            dns = packet[DNS]
            if dns.qr == 0:  # DNS query
                query_name = dns[DNSQR].qname.decode('utf-8')
                # Check if it's an IPv4 or IPv6 packet and get the source IP accordingly
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                elif packet.haslayer(IPv6):
                    src_ip = packet[IPv6].src
                # Check for the destination port (port 53 for DNS)
                if packet.sport == 53 or packet.dport == 53:
                    output.append({"Queried Domain": query_name, "Source IP": src_ip})
    return output

def get_tcpdump_data(number):
    tcpdump_data = []
    vms = ['ns0v4only', 'ns0v6only', 'ns0dualstack']
    file_types = ['v4only', 'v6only', 'dstack']

    for vm, file_type in zip(vms, file_types):
        pcap_filename = f"tcpdump-data/{file_type}-{number}.pcap"
        # Check if the file already exists
        if not os.path.exists(pcap_filename):
            scp_command = f"scp {vm}:~/{file_type}-{number}.pcap {pcap_filename}"
            subprocess.run(scp_command, shell=True)
        else:
            print(f"File {pcap_filename} already exists, skipping download.")

        data_from_pcap = extract_dns_info(pcap_filename)
        for entry in data_from_pcap:
            entry['Name Server'] = vm  # Add name server information
        tcpdump_data += data_from_pcap
    return tcpdump_data


# Assuming extract_dns_info and get_ripe_data are your existing functions


def extract_probe_id_and_domain(domain, measurement_number):
    # Convert domain to lowercase and check for duplicates
    domain = domain.lower()
    if f"ripe-{measurement_number}" in domain:
        parts = domain.split('.')
        probe_id = parts[0]
        domain_index = domain.find(f"ripe-{measurement_number}") + len(f"ripe-{measurement_number}") + 1
        actual_domain = domain[domain_index:]
        measurement_index = actual_domain.find("measurement.")
        if measurement_index != -1:
            actual_domain = actual_domain[:measurement_index]
        return probe_id, actual_domain
    return None, None


def compare_data(tcpdump_data, ripe_data, measurement_number):

    # Initialize RIPE results with empty data structures for each name server
    ripe_results = {}
    for entry in ripe_data:
        prb_id = str(entry['Probe ID'])
        if prb_id not in ripe_results:
            ripe_results[prb_id] = {
                'RIPE Data': [],
                'Queried Domains': {
                    'ns0v4only': [],
                    'ns0v6only': [],
                    'ns0dualstack': []
                }
            }

        ripe_results[prb_id]['RIPE Data'].append(entry)

    # Process TCP dump data
    for entry in tcpdump_data:
        probe_id, actual_domain = extract_probe_id_and_domain(entry['Queried Domain'], measurement_number)
        name_server = entry.get('Name Server')
        probe_id = str(probe_id)  # Ensure probe_id is a string for consistent comparison

        if actual_domain is not None:
            if probe_id in ripe_results and name_server in ripe_results[probe_id]['Queried Domains']:
                if actual_domain not in ripe_results[probe_id]['Queried Domains'][name_server]:
                    ripe_results[probe_id]['Queried Domains'][name_server].append(actual_domain)

    return ripe_results

def save_results_to_file(results, filename):
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 this.py <measurement_number> '<measurement_ids>'")
        sys.exit(1)

    measurement_number = int(sys.argv[1])
    # Convert the string representation of the list into an actual list
    measurement_ids = ast.literal_eval(sys.argv[2])

    # Run your scripts to get data
    ripe_data = get_ripe_data(measurement_ids)  # Use the correct variable here
    tcpdump_data = get_tcpdump_data(measurement_number)

    # Compare the data
    comparison_results = compare_data(tcpdump_data, ripe_data, measurement_number)


    # Output the results to a file
    filename = f"result_data/comparison_results_{measurement_number}.txt"
    save_results_to_file(comparison_results, filename)
    print(f"Results saved to {filename}")

