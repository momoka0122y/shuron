import json

def parse_file(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def merge_data(existing_data, new_data, duplicate_probes):
    for prb_id, data in new_data.items():
        if prb_id not in existing_data:
            existing_data[prb_id] = data
        else:
            duplicate_probes.add(prb_id)


            # Merge RIPE Ping Data
            existing_ping_data = existing_data[prb_id]['RIPE Ping Data']
            new_ping_data = data['RIPE Ping Data']
            for new_entry in new_ping_data:
                match_found = False
                for existing_entry in existing_ping_data:
                    if all(new_entry[k] == existing_entry[k] for k in new_entry if k != 'Status'):
                        match_found = True
                        # Update status based on priority
                        existing_status_priority = status_priority(existing_entry['Status'])
                        new_status_priority = status_priority(new_entry['Status'])
                        if new_status_priority < existing_status_priority:
                            existing_entry['Status'] = new_entry['Status']
                        break
                if not match_found:
                    existing_ping_data.append(new_entry)

            # Merge Queried Domains
            for domain_type in data['Queried Domains']:
                existing_data[prb_id]['Queried Domains'][domain_type].extend(
                    domain for domain in data['Queried Domains'][domain_type]
                    if domain not in existing_data[prb_id]['Queried Domains'][domain_type]
                )

def status_priority(status):
    priorities = {
        "Ping success": 0,
        "DNS success but Ping failure": 1,
        "No Address Family on Domain": 2,
        "Wrong Address from DNS": 3,
        "DNS failure": 4
    }
    return priorities.get(status, 5) # Default priority for unknown statuses

def analyze_ripe_results(ripe_results):
    probes_by_resolved_domains = {i: 0 for i in range(19)}
    queried_domains_count = {4: {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}}, 6: {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}} }
    status_combinations_count = {}
    total_probes_by_dns_data = 0
    total_probes_by_ping_data = 0
    total_probes_by_queried_domains = 0

    for prb_id, data in ripe_results.items():
        # Count for RIPE DNS Data
        if data['RIPE DNS Data']:
            total_probes_by_dns_data += 1
            unique_resolved_research_names = set()
            for entry in data['RIPE DNS Data']:
                if entry['ANCOUNT'] == '1':
                    unique_resolved_research_names.add(entry['Research Name'])

            count_resolved = len(unique_resolved_research_names)
            probes_by_resolved_domains[count_resolved] += 1

        # Count for Queried Domains
        tcpdump_data_found_for_probe = 0
        for ns_type, domains in data['Queried Domains'].items():
            if domains:
                tcpdump_data_found_for_probe = 1
            for domain in domains:
                queried_domains_count[ns_type][domain] = queried_domains_count[ns_type].get(domain, 0) + 1
        total_probes_by_queried_domains += tcpdump_data_found_for_probe

        # Counting status combinations for RIPE Ping Data
        if data['RIPE Ping Data']:
            total_probes_by_ping_data += 1
            status_counts = {}
            for ping_data in data['RIPE Ping Data']:
                status = ping_data['Status']
                status_counts[status] = status_counts.get(status, 0) + 1

            # Convert status counts to a hashable tuple for use as a dictionary key
            status_counts_tuple = tuple(sorted(status_counts.items()))
            status_combinations_count[status_counts_tuple] = status_combinations_count.get(status_counts_tuple, 0) + 1

    status_combinations_count_str = {str(key): value for key, value in status_combinations_count.items()}

    return probes_by_resolved_domains, queried_domains_count, status_combinations_count_str, total_probes_by_dns_data, total_probes_by_ping_data, total_probes_by_queried_domains




if __name__ == "__main__":
    combined_results = {}
    duplicate_probes = set()

    with open('txt_result_data.txt', 'r') as file:
        for line in file:
            measurement_number = line.strip()
            filename = f"result_data/comparison_results_{measurement_number}.txt"
            file_data = parse_file(filename)
            merge_data(combined_results, file_data, duplicate_probes)

    print("------------------------")
    # print(json.dumps(combined_results, indent=4))

    # Unpack return values from the function
    probes_by_resolved_domains, queried_domains_count, status_combinations_count_str, total_probes_by_dns_data, total_probes_by_ping_data, total_probes_by_queried_domains = analyze_ripe_results(combined_results)

    # Print the results
    print(json.dumps(probes_by_resolved_domains, indent=4))
    print(json.dumps(queried_domains_count, indent=4))
    print(json.dumps(status_combinations_count_str, indent=4))  # Print status combinations count
    print("Total probes by DNS Data: ", total_probes_by_dns_data)
    print("Total probes by Ping Data: ", total_probes_by_ping_data)
    print("Total probes by Queried Domains: ", total_probes_by_queried_domains)
    print("------------------------")

