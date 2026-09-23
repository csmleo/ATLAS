import networkx as nx


def build_graph(email, domain, ip, intel):
    graph = nx.DiGraph()

    graph.add_node(email, type="email")
    graph.add_node(domain, type="domain")
    graph.add_node(ip, type="ip")

    graph.add_edge(email, domain, relationship="sender-domain")
    graph.add_edge(domain, ip, relationship="resolves-to")

    if intel.get("asn") != "Unknown":
        graph.add_node(intel["asn"], type="asn")
        graph.add_edge(ip, intel["asn"], relationship="belongs-to")

    if intel.get("organization") != "Unknown":
        graph.add_node(intel["organization"], type="organization")
        graph.add_edge(
            intel["asn"],
            intel["organization"],
            relationship="operated-by"
        )

    location = f'{intel.get("city", "Unknown")}, {intel.get("country", "Unknown")}'
    graph.add_node(location, type="location")
    graph.add_edge(ip, location, relationship="located-in")

    return graph