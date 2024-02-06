import json
import itertools

def generate_ripe_atlas_curl(api_key, probe_id, email):
    base_url = "https://atlas.ripe.net/api/v2/measurements/"
    headers = {
        "Authorization": f"Key {api_key}",
        "Content-Type": "application/json"
    }
    domain_types = ['dstack', 'v4only', 'v6only']
    domain_mapping = {'dstack': 'd', 'v4only': '4', 'v6only': '6'}
    query_types = ['A', 'AAAA']
    definitions = []

    for domain_pair in itertools.product(domain_types, repeat=2):
        for query_type in query_types:
            description_prefix = ''.join([domain_mapping[d] for d in domain_pair]) + query_type
            description = f"{description_prefix}-{probe_id}"
            domain = f"RIPE-{probe_id}.vm.{'.'.join(domain_pair)}.measurement.dnsv6-atlas-res.measurement.network."
            definition = {
                "type": "dns",
                "af": 4,
                "resolve_on_probe": True,
                "description": description,
                "query_class": "IN",
                "query_type": query_type,
                "use_macros": False,
                "protocol": "UDP",
                "udp_payload_size": 512,
                "retry": 0,
                "skip_dns_check": False,
                "include_qbuf": False,
                "include_abuf": True,
                "prepend_probe_id": True,
                "set_rd_bit": False,
                "set_do_bit": False,
                "set_cd_bit": False,
                "timeout": 5000,
                "use_probe_resolver": True,
                "set_nsid_bit": True,
                "query_argument": domain
            }
            definitions.append(definition)

    data = {
        "definitions": definitions,
        "probes": [{"type": "area", "value": "WW", "requested": 1000}],
        "is_oneoff": True,
        "bill_to": email
    }

    curl_command = f"curl -H 'Authorization: {headers['Authorization']}' -H 'Content-Type: {headers['Content-Type']}' -X POST -d '{json.dumps(data)}' {base_url}"
    return curl_command

# Example usage
api_key = "a5427ff6-3f29-4ddb-8727-a30d3fa99a8f"
email = "miki98765423@gmail.com"

probe_id = "10039"
curl_command = generate_ripe_atlas_curl(api_key, probe_id, email)
print(curl_command)

