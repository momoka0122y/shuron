def analyze_ripe_results(ripe_results):
    probes_by_resolved_domains = {i: 0 for i in range(19)}
    queried_domains_count = {4: {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}}, 6: {'ns0v4only': {}, 'ns0v6only': {}, 'ns0dualstack': {}} }
    # ... existing code for status_combinations_count and total probes ...

    for prb_id, data in ripe_results.items():
        # ... existing code for counting RIPE DNS Data and RIPE Ping Data ...

        # Count for Queried Domains
        for af in [4, 6]:
            for ns_type, domains in data['Queried Domains'][af].items():
                for domain in domains:
                    queried_domains_count[af][ns_type][domain] = queried_domains_count[af][ns_type].get(domain, 0) + 1

    # ... existing code for status_combinations_count_str ...

    return probes_by_resolved_domains, queried_domains_count, status_combinations_count_str, total_probes_by_dns_data, total_probes_by_ping_data, total_probes_by_queried_domains
