import ipaddress

# ATLAS Intelligence synthetic test dataset.
# Values are part of ATLAS's evaluation dataset and
# do not represent real-world malicious attribution against organizations.
ATLAS_INTEL = {
    "91.243.44.12": {
        "country": "Veloria",
        "city": "Northbridge",
        "asn": "AS40127",
        "organization": "Northstar Transit Networks",
        "reputation": "SUSPICIOUS",
        "sources": ["ATLAS Intelligence"]
    },
    "185.220.101.47": {
        "country": "Kaelen",
        "city": "Oakhaven",
        "asn": "AS51892",
        "organization": "Sentry Relay Solutions",
        "reputation": "SUSPICIOUS",
        "sources": ["ATLAS Intelligence"]
    },
    "209.85.220.41": {
        "country": "United States",
        "city": "Mountain View",
        "asn": "AS15169",
        "organization": "Google LLC",
        "reputation": "CLEAN",
        "sources": ["ATLAS Intelligence"]
    },
    "209.85.234.182": {
        "country": "United States",
        "city": "Mountain View",
        "asn": "AS15169",
        "organization": "Google LLC",
        "reputation": "CLEAN",
        "sources": ["ATLAS Intelligence"]
    },
    "198.51.100.24": {
        "country": "Veloria",
        "city": "Northbridge",
        "asn": "AS40127",
        "organization": "Northstar Transit Networks",
        "reputation": "SUSPICIOUS",
        "sources": ["ATLAS Intelligence"]
    },
    "203.0.113.88": {
        "country": "Zephyria",
        "city": "Ironshore",
        "asn": "AS39811",
        "organization": "Cobalt Cloud Infrastructure",
        "reputation": "SUSPICIOUS",
        "sources": ["ATLAS Intelligence"]
    },
    "192.0.2.1": {
        "country": "Alveria",
        "city": "Silverfall",
        "asn": "AS29014",
        "organization": "Apex Global Host",
        "reputation": "CLEAN",
        "sources": ["ATLAS Intelligence"]
    }
}


def enrich_ip(ip: str) -> dict:
    if not ip or ip == "Unknown":
        return {
            "country": "Unknown",
            "city": "Unknown",
            "asn": "Unknown",
            "organization": "Unknown",
            "reputation": "UNKNOWN",
            "sources": ["ATLAS Intelligence"]
        }

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {
                "country": "Internal / RFC 1918",
                "city": "Private Network",
                "asn": "N/A (Private)",
                "organization": "Local Infrastructure",
                "reputation": "INTERNAL",
                "sources": ["ATLAS Intelligence"]
            }
    except ValueError:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "asn": "Unknown",
            "organization": "Unknown",
            "reputation": "UNKNOWN",
            "sources": ["ATLAS Intelligence"]
        }

    return ATLAS_INTEL.get(ip, {
        "country": "Unknown",
        "city": "Unknown",
        "asn": "Unknown",
        "organization": "Unknown",
        "reputation": "UNKNOWN",
        "sources": ["ATLAS Intelligence"]
    })