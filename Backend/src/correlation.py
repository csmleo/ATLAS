def find_shared_ip_correlations(records):
    ip_map = {}

    for record in records:
        ip = record["ip"]
        domain = record["domain"]

        ip_map.setdefault(ip, []).append(domain)

    correlations = []

    for ip, domains in ip_map.items():
        unique_domains = list(set(domains))

        if len(unique_domains) > 1:
            correlations.append({
                "type": "shared-ip",
                "ip": ip,
                "domains": unique_domains,
                "confidence": 0.90,
                "finding": "Multiple domains share the same infrastructure IP."
            })

    return correlations