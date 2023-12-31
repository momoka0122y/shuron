import json
import requests

def get_ripe_data(url):
    output = []
    # Fetch the data from the URL
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to retrieve data")
        return

    data = response.json()

    # Process each entry
    # Iterate through each entry in the data
    for entry in data:
        prb_id = entry['prb_id']
        from_ip = entry['from']

        for resultset in entry['resultset']:
            dst_addr = resultset['dst_addr']
            src_addr = resultset['src_addr']
            ancount = resultset['result']['ANCOUNT']
            ancount_status = '0' if ancount == 0 else 1

            output.append({
                "Probe ID": prb_id,
                "From": from_ip,
                "Destination Addr": dst_addr,
                "Source Addr": src_addr,
                "ANCOUNT": ancount_status
            })

    # Output the data in JSON format
    print(json.dumps(output, indent=4))

# URL of the RIPE data
url = "https://atlas.ripe.net/api/v2/measurements/65316649/results/"

get_ripe_data(url)
