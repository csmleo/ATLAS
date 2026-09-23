import os
import sys

# Allow importing from src when running from project root
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.infrastructure_graph import build_graph
from src.threat_intel import enrich_ip

email = "security-alerts@micr0soft-account-verify.com"
domain = "micr0soft-secure-login"
ip = "91.243.44.12"

intel = enrich_ip(ip)
graph = build_graph(email, domain, ip, intel)

# Save inside reportes folder
output_file = os.path.join("reportes", "infrastructure_graph.txt")

with open(output_file, "w", encoding="utf-8") as f:
    f.write("ATLAS INFRASTRUCTURE GRAPH\n")
    f.write("=" * 40 + "\n\n")

    f.write("NODES\n")
    for node, data in graph.nodes(data=True):
        f.write(f"• {node} ({data['type']})\n")

    f.write("\nRELATIONSHIPS\n")
    for source, target, data in graph.edges(data=True):
        f.write(f"• {source} ---> {target} [{data['relationship']}]\n")

print(f"Graph generated successfully: {output_file}")