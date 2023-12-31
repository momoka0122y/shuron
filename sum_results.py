import json

def parse_file(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def merge_data(existing_data, new_data, duplicate_probes):
    for prb_id, data in new_data.items():
        if prb_id not in existing_data:
            existing_data[prb_id] = data
        else:
            # Handle duplicate probes
            duplicate_probes.add(prb_id)

            # Merge RIPE Data
            existing_ripe_data = existing_data[prb_id]['RIPE Data']
            new_ripe_data = data['RIPE Data']
            for new_entry in new_ripe_data:
                match_found = False
                for existing_entry in existing_ripe_data:
                    if all(new_entry[k] == existing_entry[k] for k in new_entry if k != 'ANCOUNT'):
                        match_found = True
                        existing_entry['ANCOUNT'] = max(existing_entry['ANCOUNT'], new_entry['ANCOUNT'])
                        break
                if not match_found:
                    existing_ripe_data.append(new_entry)

            # Merge Queried Domains
            for domain_type in data['Queried Domains']:
                existing_data[prb_id]['Queried Domains'][domain_type].extend(
                    domain for domain in data['Queried Domains'][domain_type]
                    if domain not in existing_data[prb_id]['Queried Domains'][domain_type]
                )

def analyze_ripe_results(ripe_results):
    probes_by_resolved_domains = {i: 0 for i in range(19)}
    queried_domains_count = {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}}
    total_probes = len(ripe_results)

    for prb_id, data in ripe_results.items():
        # print(prb_id,data)
        unique_resolved_research_names = set()
        for entry in data['RIPE Data']:
            # print("Before if")
            if entry['ANCOUNT'] == '1':
                unique_resolved_research_names.add(entry['Research Name'])
                # print("if ==1   //////////////////")
                # print(prb_id,entry)


        # print(prb_id,unique_resolved_research_names)
        count_resolved = len(unique_resolved_research_names)
        probes_by_resolved_domains[count_resolved] += 1

        for ns_type, domains in data['Queried Domains'].items():
            for domain in domains:
                queried_domains_count[ns_type][domain] = queried_domains_count[ns_type].get(domain, 0) + 1

    return probes_by_resolved_domains, queried_domains_count, total_probes


if __name__ == "__main__":
    combined_results = {}
    duplicate_probes = set()

    with open('txt_result_data.txt', 'r') as file:
        for line in file:
            print("new file to open")
            print(line)
            measurement_number = line.strip()
            filename = f"result_data/comparison_results_{measurement_number}.txt"
            file_data = parse_file(filename)
            merge_data(combined_results, file_data, duplicate_probes)

    print("------------------------")
    # print(duplicate_probes)
    print(json.dumps(combined_results, indent=4))
    # Output the combined data
    print("------------------------")
    print()
    probes_by_resolved_domains, queried_domains_count, total_probes = analyze_ripe_results(combined_results)
    print(json.dumps(probes_by_resolved_domains, indent=4))
    print(json.dumps(queried_domains_count, indent=4))
    print(probes_by_resolved_domains)
    print(queried_domains_count)
    print(total_probes)
    print("------------------------")
