import json
import requests
import sys
import itertools
import subprocess
import os  # Add this line to import the os module
from scapy.all import rdpcap, DNS, DNSQR, IP, IPv6
import ast
import base64
from dnslib import DNSRecord
from ipaddress import ip_address
from ipaddress import ip_address, AddressValueError



def process_ping_data(data, research_name):
    output = []
    valid_dst_addresses = {"141.39.220.83", "141.39.220.84", "141.39.220.85", "2a0d:8d04:a100:0:141:39:220:83", "2a0d:8d04:a100:0:141:39:220:84", "2a0d:8d04:a100:0:141:39:220:85"}

    for entry in data:
        # Extract relevant fields from Ping data
        prb_id = entry.get('prb_id')
        from_ip = entry.get('from')
        dst_name = entry.get('dst_name')
        dst_addr = entry.get('dst_addr')
        avg_rtt = entry.get('avg')
        result = entry.get('result', [{}])
        af = entry.get('af')

        # Check if the destination address is one of the valid addresses

        if result[0].get('error') == "dns resolution failed: non-recoverable failure in name resolution":
            if "vm.v4only." in dst_name and af == 6 or "vm.v6only." in dst_name and af == 4:
                status = "No Address Family on Domain"
            else:
                status = "DNS failure"
        elif result[0].get('error') == "dns resolution failed: nodename nor servname provided, or not known":
            status = "No Address Family on Domain"
        elif dst_addr not in valid_dst_addresses:
            status = "Wrong Address from DNS"
        elif avg_rtt != -1:
            status = "Ping success"
        else:
            status = "DNS success but Ping failure"

        output.append({
            "Probe ID": prb_id,
            "From": from_ip,
            "Destination Name": dst_name,
            "Destination Addr": dst_addr,  # Include destination address in the output
            "Average RTT": avg_rtt,
            "Status": status,
            "Research Name": research_name,
            "Address Family": af
        })
    return output

def is_valid_ip(address):
    try:
        ip_address(address)
        return True
    except ValueError:
        return False

def decode_abuf(abuf):
    try:
        dns_response = base64.b64decode(abuf)
        dns_record = DNSRecord.parse(dns_response)
        return dns_record
    except Exception as e:
        print(f"Error decoding abuf: {e}")
        return None  # Return None or a suitable default value

def get_answer(abuf):
    decoded_dns_record = decode_abuf(abuf)
    if decoded_dns_record and decoded_dns_record.rr:
        return str(decoded_dns_record.rr[0].rdata)
    return ""

def process_dns_data(data, research_name):
    output = []
    valid_dst_addresses = {"141.39.220.83", "141.39.220.84", "141.39.220.85", 
                           "2a0d:8d04:a100:0:141:39:220:83", "2a0d:8d04:a100:0:141:39:220:84", 
                           "2a0d:8d04:a100:0:141:39:220:85"}
    for entry in data:
        prb_id = entry.get('prb_id')
        from_ip = entry.get('from')

        for resultset in entry.get('resultset', []):
            dst_addr = resultset.get('dst_addr')
            src_addr = resultset.get('src_addr')
            result = resultset.get('result', {})
            ancount = result.get('ANCOUNT', -1)
            ancount_status = '1' if ancount == 1 else '0'
            answer_address = ""
            abuf = result.get('abuf', None)

            if ancount_status == '1':
                
                # Check if abuf is not None
                if abuf:
                    answer_address = get_answer(abuf)
                    # Check if the extracted IP address is valid
                    if not answer_address or not is_valid_ip(answer_address):
                        ancount_status = '-2'
                        print("abuf" )
                        print(abuf)

                    if is_valid_ip(answer_address) and ip_address(answer_address) not in map(ip_address, valid_dst_addresses):
                        ancount_status = '-1'
                        print("Answer Address")
                        print(answer_address)
                else:
                    print()
                    ancount_status = '0'

            output.append({
                "Probe ID": prb_id,
                "From": from_ip,
                "Destination Addr": dst_addr,
                "Source Addr": src_addr,
                "ANCOUNT": ancount_status,
                "abuf": abuf,
                "Answer Address": answer_address,
                "Research Name": research_name
            })

    return output

def get_ripe_data(measurement_ids):
    all_data_dns = []  # Initialize as an empty list
    all_data_ping = []  # Initialize as an empty list
    domain_types = ['dstack', 'v4only', 'v6only']
    query_types = ['A', 'AAAA']
    i = 0
    for domain_pair in itertools.product(domain_types, repeat=2):
        for query_type in query_types:
            current_id = measurement_ids[i]
            i += 1
            url = f"https://atlas.ripe.net/api/v2/measurements/{current_id}/results/"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()

                # Determine if the data is DNS or Ping based on the 'type' field in the data
                if data and 'type' in data[0]:
                    data_type = data[0]['type']
                    domain_pair_str = "_".join(domain_pair)
                    research_name = f"{domain_pair_str}_{query_type}_{data_type}"
                    if data_type == 'dns':
                        # Process DNS data
                        all_data_dns.extend(process_dns_data(data, research_name))
                    elif data_type == 'ping':
                        # Process Ping data
                        all_data_ping.extend(process_ping_data(data, research_name))
                    else:
                        print(f"Unknown data type for measurement ID {current_id}")
                else:
                    print(f"No data type found for measurement ID {current_id}")
            else:
                print(f"Failed to retrieve data for measurement ID {current_id}")

    return all_data_dns, all_data_ping


def extract_dns_info(pcap_file):
    output = []
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and (packet.haslayer(IP) or packet.haslayer(IPv6)):
            dns = packet[DNS]
            if dns.qr == 0:  # DNS query
                query_name = dns[DNSQR].qname.decode('utf-8')
                # Check if it's an IPv4 or IPv6 packet and get the source IP accordingly
                if packet.sport == 53 or packet.dport == 53:
                    if packet.haslayer(IP):
                        src_ip = packet[IP].src
                        output.append({"Queried Domain": query_name, "Source IP": src_ip, "Address Family": 4})
                    elif packet.haslayer(IPv6):
                        src_ip = packet[IPv6].src
                        output.append({"Queried Domain": query_name, "Source IP": src_ip, "Address Family": 6})
    return output

def get_tcpdump_data(number):
    tcpdump_data = []
    vms = ['ns0v4only', 'ns0v6only', 'ns0dualstack']
    file_types = ['v4only', 'v6only', 'dstack']

    for vm, file_type in zip(vms, file_types):
        pcap_filename = f"tcpdump-data/{file_type}-{number}.pcap"

        # Attempt to download the file if it does not exist
        if not os.path.exists(pcap_filename):
            scp_command = f"scp {vm}:~/{file_type}-{number}.pcap {pcap_filename}"
            subprocess.run(scp_command, shell=True)

            # Check again if the file exists
            if not os.path.exists(pcap_filename):
                print(f"Failed to download {pcap_filename}, skipping.")
                continue

        try:
            data_from_pcap = extract_dns_info(pcap_filename)
            for entry in data_from_pcap:
                entry['Name Server'] = vm  # Add name server information
            tcpdump_data += data_from_pcap
        except FileNotFoundError:
            print(f"File {pcap_filename} not found, skipping.")
            continue

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


def compare_data(tcpdump_data, ripe_data_dns, ripe_data_ping, measurement_number):

    # Initialize RIPE results with the new data structure
    ripe_results = {}
    for entry in ripe_data_dns + ripe_data_ping:
        prb_id = str(entry['Probe ID'])
        if prb_id not in ripe_results:
            ripe_results[prb_id] = {
                'RIPE DNS Data': [],
                'RIPE Ping Data': [],
                'Queried Domains': {
                    4: {'ns0v4only': [], 'ns0v6only': [], 'ns0dualstack': []},
                    6: {'ns0v4only': [], 'ns0v6only': [], 'ns0dualstack': []}
                }
            }

        if 'Average RTT' in entry:  # This indicates it's Ping data
            ripe_results[prb_id]['RIPE Ping Data'].append(entry)
        else:  # Otherwise, it's DNS data
            ripe_results[prb_id]['RIPE DNS Data'].append(entry)

    # Process TCP dump data for DNS
    for entry in tcpdump_data:
        probe_id, actual_domain = extract_probe_id_and_domain(entry['Queried Domain'], measurement_number)
        name_server = entry.get('Name Server')
        address_family = entry.get('Address Family')
        # probe_id = str(probe_id)  # Ensure probe_id is a string for consistent comparison
        if probe_id is None or probe_id not in ripe_results:
            continue  # Skip if probe_id is None
        if actual_domain is not None and address_family in ripe_results[probe_id]['Queried Domains']:
            if actual_domain not in ripe_results[probe_id]['Queried Domains'][address_family][name_server]:
                ripe_results[probe_id]['Queried Domains'][address_family][name_server].append(actual_domain)
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
    ripe_data_dns, ripe_data_ping = get_ripe_data(measurement_ids)  # Use the correct variable here
    tcpdump_data = get_tcpdump_data(measurement_number)

    # Compare the data
    comparison_results = compare_data(tcpdump_data, ripe_data_dns, ripe_data_ping, measurement_number)


    # Output the results to a file
    filename = f"result_data/comparison_results_{measurement_number}.txt"
    save_results_to_file(comparison_results, filename)
    print(f"Results saved to {filename}")

