import json

def parse_file(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def merge_data(existing_data, new_data, duplicate_probes):
    for prb_id, data in new_data.items():
        if prb_id not in existing_data:
            # Initialize existing_data[prb_id] with new_data[prb_id]
            existing_data[prb_id] = data

            # Removing duplicates within the new data
            # For RIPE DNS Data
            unique_dns_entries = {}
            for dns_entry in data['RIPE DNS Data']:
                research_name = dns_entry['Research Name']
                if research_name in unique_dns_entries:
                    # Compare 'ANCOUNT' and keep the one with higher value
                    if int(dns_entry['ANCOUNT']) > int(unique_dns_entries[research_name]['ANCOUNT']):
                        unique_dns_entries[research_name] = dns_entry
                else:
                    unique_dns_entries[research_name] = dns_entry

            # Update the existing data with unique DNS entries
            existing_data[prb_id]['RIPE DNS Data'] = list(unique_dns_entries.values())

        else:
            duplicate_probes.add(prb_id)

            # Merge RIPE Ping Data
            existing_ping_data = existing_data[prb_id]['RIPE Ping Data']
            new_ping_data = data['RIPE Ping Data']
            for new_entry in new_ping_data:
                match_found = False
                for existing_entry in existing_ping_data:
                    # Extract the last string after '.vm.' in the Destination Names
                    new_dest_name_suffix = new_entry['Destination Name'].split('.vm.')[-1]
                    existing_dest_name_suffix = existing_entry['Destination Name'].split('.vm.')[-1]

                    # Check if the entries are the same based on the new criteria
                    if (new_entry['Probe ID'] == existing_entry['Probe ID'] and
                        new_entry['Address Family'] == existing_entry['Address Family'] and
                        new_dest_name_suffix == existing_dest_name_suffix):
                        match_found = True
                        # Update status based on priority
                        existing_status_priority = status_priority(existing_entry['Status'])
                        new_status_priority = status_priority(new_entry['Status'])
                        if new_status_priority < existing_status_priority:
                            existing_entry['Status'] = new_entry['Status']
                            existing_entry['Average RTT'] = new_entry['Average RTT']
                            existing_entry['Destination Addr'] = new_entry['Destination Addr']
                        break
                if not match_found:
                    existing_ping_data.append(new_entry)

            # Merge Queried Domains
            for domain_type in data['Queried Domains']:
                existing_domains = existing_data[prb_id]['Queried Domains'][domain_type]
                new_domains = data['Queried Domains'][domain_type]

                for domain in new_domains:
                    if domain not in existing_domains:
                        existing_domains.append(domain)

            existing_dns_data = existing_data[prb_id]['RIPE DNS Data']
            new_dns_data = data['RIPE DNS Data']
            for new_entry in new_dns_data:
                match_found = False
                for existing_entry in existing_dns_data:
                    # Check if the entries are the same based on the 'Research Name'
                    if new_entry['Research Name'] == existing_entry['Research Name']:
                        match_found = True
                        # Compare 'ANCOUNT' and keep the one with higher value
                        if int(new_entry['ANCOUNT']) > int(existing_entry['ANCOUNT']):
                            existing_entry.update(new_entry)
                        break
                if not match_found:
                    existing_dns_data.append(new_entry)
def status_priority(status):
    priorities = {
        "Ping success": 0,
        "DNS success but Ping failure": 1,
        "No Address Family on Domain": 2,
        "Wrong Address from DNS": 3,
        "DNS failure": 4
    }
    return priorities.get(status, 5) # Default priority for unknown statuses

def generate_latex_table(data):
    total_count = sum(data.values())
    header = "\\begin{table}[tbhp]\n" \
             "    \\centering\n" \
             "    \\caption{Ping Measurement Details}\n" \
             "    \\label{table:ping_measurement_details}\n" \
             "    \\rowcolors{2}{gray!25}{white}\n" \
             "    \\begin{tabular}{|r|r|r|r|r|!{\\vrule width 2pt}r|}\n" \
             "    \\hline\n" \
             "    \\rowcolor{gray!50}\n" \
             "    \\textbf{\\small{Ping Success}} & \\textbf{\\small{No Address}} & " \
             "\\textbf{\\small{DNS Failure}} & \\textbf{\\small{Ping Failure}} & " \
             "\\textbf{\\small{Wrong Address}} & \\textbf{Count} \\\\\n" \
             "    \\hline\n"
    
    body = ""
    for key, count in data.items():
        # Parse the key to get the individual components
        components = key.strip("()").split("), (")
        # Create a dictionary to map each category to its value
        categories = {"Ping success": 0, "No Address Family on Domain": 0,
                      "DNS failure": 0, "DNS success but Ping failure": 0, "Wrong Address from DNS": 0}
        for component in components:
            category, value = component.strip("'()").split("', ")
            categories[category] = value
        
        # Calculate percentage and format it
        percentage = (count / total_count) * 100
        formatted_percentage = f"{percentage:05.2f}"  # Format to always have two digits before and after the decimal point

        # Construct the row string
        row = f"    {categories['Ping success']} & {categories['No Address Family on Domain']} & " \
              f"{categories['DNS failure']} & {categories['DNS success but Ping failure']} & " \
              f"{categories['Wrong Address from DNS']} & {count} ({formatted_percentage}\\%) \\\\\n"
        
        body += row + "    \\hline\n"

    footer = "    \\end{tabular}\n" \
             "\\end{table}\n"

    return header + body + footer

def generate_dns_latex_table(data):
    # Filter out the non-tuple keys and sum only the relevant values
    filtered_data = {key: value for key, value in data.items() if key.startswith("(('")}
    total_count = sum(filtered_data.values())

    header = "\\begin{table}[tbhp]\n" \
             "    \\centering\n" \
             "    \\caption{DNS Measurement Results}\n" \
             "    \\label{table:DNS_measurement_results}\n" \
             "    \\rowcolors{2}{gray!25}{white}\n" \
             "    \\begin{tabular}{|r|r|r|r|!{\\vrule width 2pt}r|}\n" \
             "    \\hline\n" \
             "    \\rowcolor{gray!50}\n" \
             "    \\textbf{\\small{Resolution Success}} & \\textbf{\\small{Resolution Failure}} & " \
             "\\textbf{\\small{Wrong Address}} & \\textbf{\\small{Other}} & \\textbf{Count} \\\\\n" \
             "    \\hline\n"
    
    body = ""
    for key, count in filtered_data.items():
        # Parse the key to get the individual components
        components = key.strip("()").split("), (")
        categories = {"1": 0, "0": 0, "-1": 0, "-2": 0}
        for component in components:
            if component:  # Check if component is not empty
                category, value = component.strip("'()").split("', ")
                categories[category] = value
        
        # Calculate percentage and format it
        percentage = (count / total_count) * 100
        formatted_percentage = f"{percentage:05.2f}"  # Format to always have two digits before and after the decimal point

        # Construct the row string
        row = f"    {categories['1']} & {categories['0']} & " \
              f"{categories['-1']} & {categories['-2']} & {count} ({formatted_percentage}\\%) \\\\\n"
   
        body += row + "    \\hline\n"

    footer = "    \\end{tabular}\n" \
             "\\end{table}\n"

    return header + body + footer


def analyze_ripe_results(ripe_results):
    probes_by_resolved_domains = {i: 0 for i in range(19)}
    queried_domains_count = {'4': {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}}, '6': {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}} }
    status_combinations_count = {}
    total_probes_by_dns_data = 0
    total_probes_by_ping_data = 0
    total_probes_by_queried_domains = 0

    for prb_id, data in ripe_results.items():
        # Count for RIPE DNS Data
        if data['RIPE DNS Data']:
            total_probes_by_dns_data += 1
            unique_entries = {}

            # Selecting the entry with the highest 'ANCOUNT' for each 'Research Name'
            for entry in data['RIPE DNS Data']:
                research_name = entry['Research Name']
                ancount = int(entry['ANCOUNT'])
                if research_name not in unique_entries or ancount > int(unique_entries[research_name]['ANCOUNT']):
                    unique_entries[research_name] = entry

            # Counting 'ANCOUNT' values from the unique entries
            status_counts = {}
            for entry in unique_entries.values():
                ancount = entry['ANCOUNT']
                status_counts[ancount] = status_counts.get(ancount, 0) + 1
            # if status_counts['1'] and status_counts['1'] == 24:
            #      print("unique_entries")
            #      print(json.dumps(unique_entries, indent=4))
            #      print("data['RIPE DNS Data']")
            #      print(data['RIPE DNS Data'])

            # Convert status counts to a hashable tuple for use as a dictionary key
            status_counts_tuple = tuple(sorted(status_counts.items()))

            probes_by_resolved_domains[status_counts_tuple] = probes_by_resolved_domains.get(status_counts_tuple, 0) + 1

        # Count for Queried Domains
        tcpdump_data_found_for_probe = 0


        for af in ['4', '6']:  # Changed to string keys
            queried_domains_af = data['Queried Domains'].get(af)
            if queried_domains_af:
                for ns_type, domains in queried_domains_af.items():
                    if domains:
                        tcpdump_data_found_for_probe = 1
                    for domain in domains:
                        queried_domains_count[af][ns_type][domain] = queried_domains_count[af][ns_type].get(domain, 0) + 1
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

    status_combinations_count_str = {str(key): value for key, value in status_combinations_count.items()}   # Convert keys to strings for JSON serialization
    probes_by_resolved_domains_str = {str(key): value for key, value in probes_by_resolved_domains.items()}

    return probes_by_resolved_domains_str, queried_domains_count, status_combinations_count_str, total_probes_by_dns_data, total_probes_by_ping_data, total_probes_by_queried_domains




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

    # Unpack return values from the function
    probes_by_resolved_domains, queried_domains_count, status_combinations_count_str, total_probes_by_dns_data, total_probes_by_ping_data, total_probes_by_queried_domains = analyze_ripe_results(combined_results)

    # Print the results
    sorted_probes_by_resolved_domains = dict(sorted(probes_by_resolved_domains.items(), key=lambda item: item[1], reverse=True))
    print(json.dumps(sorted_probes_by_resolved_domains, indent=4))
    print(generate_dns_latex_table(sorted_probes_by_resolved_domains))
    print(json.dumps(queried_domains_count, indent=4))

    # Sort status_combinations_count_str by values and convert to a sorted dictionary
    sorted_status_combinations_count = dict(sorted(status_combinations_count_str.items(), key=lambda item: item[1], reverse=True))
    print(json.dumps(sorted_status_combinations_count, indent=4))  # Print sorted status combinations count
    latex_table = generate_latex_table(sorted_status_combinations_count)
    print(latex_table)
    

    print("Total probes by DNS Data: ", total_probes_by_dns_data)
    print("Total probes by Ping Data: ", total_probes_by_ping_data)
    print("Total probes by Queried Domains: ", total_probes_by_queried_domains)
    print("------------------------")

