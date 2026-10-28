"""
Interactive graph rendering for Streamlit (vis-network, loaded from a CDN).

Takes plain dicts so the same renderer serves the RAG pipeline and the
free-form Cypher runner:
  nodes: {"id", "label", "group", "title", "seed"}
  edges: {"from", "to", "label"}
"""
import json

import streamlit.components.v1 as components

COLORS = {
    "ThreatActor": "#e5484d",
    "Vulnerability": "#f5a524",
    "Software": "#3e8ef7",
    "Report": "#30a46c",
}
DEFAULT_COLOR = "#8b8d98"

_TEMPLATE = """
<div style="font:12px sans-serif;color:#cfd3d8;margin-bottom:6px">{legend}</div>
<div id="net" style="height:{height}px;border:1px solid #2b363c;border-radius:8px;background:#0e1117"></div>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<script>
const nodes = new vis.DataSet({nodes});
const edges = new vis.DataSet({edges});
new vis.Network(document.getElementById("net"), {{nodes, edges}}, {{
  nodes: {{shape: "dot", size: 16, font: {{color: "#e9eff0", size: 12}}, borderWidth: 1}},
  edges: {{arrows: "to", color: {{color: "#6d7a80", highlight: "#e9eff0"}},
           font: {{color: "#93a3a9", size: 10, strokeWidth: 0, align: "middle"}}, smooth: {{type: "dynamic"}}}},
  physics: {{solver: "forceAtlas2Based", stabilization: {{iterations: 150}}}},
  interaction: {{hover: true, tooltipDelay: 100}}
}});
</script>
"""


def render_graph(nodes, edges, height=520):
    if not nodes:
        components.html(
            '<div style="font:14px sans-serif;color:#93a3a9;padding:12px">'
            "No nodes to draw. Return nodes or relationships (not just properties) "
            "to see a graph.</div>",
            height=60,
        )
        return

    groups = []
    vis_nodes = []
    for n in nodes:
        group = n.get("group", "Node")
        if group not in groups:
            groups.append(group)
        color = COLORS.get(group, DEFAULT_COLOR)
        vis_nodes.append({
            "id": n["id"],
            "label": n["label"],
            "title": n.get("title", ""),
            "color": {"background": color, "border": "#ffffff" if n.get("seed") else color},
            "borderWidth": 4 if n.get("seed") else 1,
            "size": 24 if n.get("seed") else 16,
        })

    legend = " ".join(
        f'<span style="color:{COLORS.get(g, DEFAULT_COLOR)}">&#9679;</span> {g}' for g in groups
    )
    if any(n.get("seed") for n in nodes):
        legend += " &nbsp;|&nbsp; white ring = vector-search seed"

    # "</" would end the inline script early if it appeared in node text
    dump = lambda o: json.dumps(o).replace("</", "<\\/")
    components.html(
        _TEMPLATE.format(
            nodes=dump(vis_nodes), edges=dump(edges), height=height, legend=legend
        ),
        height=height + 40,
    )
