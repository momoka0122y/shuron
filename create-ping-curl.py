import json
import itertools

def generate_ripe_atlas_ping_curl(api_key, measurement_id, email):
    base_url = "https://atlas.ripe.net/api/v2/measurements/"
    headers = {
        "Authorization": f"Key {api_key}",
        "Content-Type": "application/json"
    }
    domain_types = ['dstack', 'v4only', 'v6only']
    ip_versions = [4, 6]
    definitions = []

    for domain_pair, ip_version in itertools.product(itertools.product(domain_types, repeat=2), ip_versions):
        description = f"ping-{''.join(domain_pair)}-ipv{ip_version}-{measurement_id}"
        # Using the ${probeid} macro as a string literal
        domain = f"RIPE-{measurement_id}.$p.vm.{'.'.join(domain_pair)}.measurement.dnsv6-atlas-res.measurement.network."

        definition = {
            "type": "ping",
            "af": ip_version,
            "resolve_on_probe": True,
            "description": description,
            "packets": 3,
            "size": 48,
            "skip_dns_check": True,
            "include_probe_id": True,
            "use_macros": True,
            "target": domain
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
api_key = "94b06c16-d66c-42c8-befd-3c83fcfa172d"
email = "jijiotouch@g.ecc.u-tokyo.ac.jp"

measurement_id = "20029"
curl_command = generate_ripe_atlas_ping_curl(api_key, measurement_id, email)
print(curl_command)
