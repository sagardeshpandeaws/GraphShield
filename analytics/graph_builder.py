import re
from pyvis.network import Network

def _parse_path(text):
    if not text:
        return []
    normalized = re.sub(r"\s*(-->|->|=>|→|➜|>>)\s*", "|", text)
    return [n.strip() for n in normalized.split("|") if n.strip()]

def create_attack_graph(chains, output):
    net = Network(height="700px", width="100%", bgcolor="#111111", font_color="white")
    for c in chains:
        path = c.get("attack_path_nodes") or _parse_path(c.get("attack_path", ""))
        if len(path) < 2:
            continue
        for i in range(len(path) - 1):
            net.add_node(path[i])
            net.add_node(path[i + 1])
            net.add_edge(path[i], path[i + 1])
    net.save_graph(output)