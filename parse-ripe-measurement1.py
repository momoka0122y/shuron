import json
import requests
import sys
import itertools

def get_ripe_data(base_id):
    domain_types = ['dstack', 'v4only', 'v6only']
    query_types = ['A', 'AAAA']

    for domain_pair in itertools.product(domain_types, repeat=2):
        for query_type in query_types:
            current_id = base_id
            research_name = f"{domain_pair[0]}_{domain_pair[1]}_{query_type}"

            # Construct the URL with the current ID
            url = f"https://atlas.ripe.net/api/v2/measurements/{current_id}/results/"
            print(f"Fetching data for {research_name} from {url}")

            # Fetch and process the data
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                process_data(data, research_name)
            else:
                print(f"Failed to retrieve data for {research_name}")

            # Increment the base ID for the next iteration
            base_id += 1

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
            ancount_status = '0' if ancount == 0 else '0'

            output.append({
                "Probe ID": prb_id,
                "From": from_ip,
                "Destination Addr": dst_addr,
                "Source Addr": src_addr,
                "ANCOUNT": ancount_status,
                "Research Name": research_name
            })

    # Output the data in JSON format
    print(json.dumps(output, indent=4))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse-ripe-measurement.py <starting_id>")
        sys.exit(1)

    starting_id = int(sys.argv[1])
    get_ripe_data(starting_id)

