"""
    Draw a graph of machoc-linked samples.
    The family is displayed with a random color for each.

    This file is part of Polichombr

        (c) ANSSI-FR 2016
"""
import networkx as nx
import requests
import graphviz
import random
import matplotlib

matplotlib.use("svg")
import matplotlib.pyplot as plt

print "Downloading sample list"
req = requests.get("http://localhost:5000/api/1.0/samples")

samples = req.json()["samples"]

print "Creating graph"
G = nx.Graph()

edges = set()
nodes = []
nodes_label = {}

counter = 0
for index, s in enumerate(samples):
    if len(s["linked_samples"]) >= 1:
        for link in s["linked_samples"]:
            if "machoc" in link["match_type"]:
                G.add_node(s["id"])
                nodes.append(s["id"])
                nodes_label[s["id"]] = str(s["id"])
                edges.add((s["id"], link["sid_2"]))
                G.add_edge(s["id"], link["sid_2"])

print "Graph is %d nodes with %d edges" % (len(G.nodes()), len(G.edges()))

families = requests.get("http://localhost:5000/api/1.0/families/")

families = families.json()["families"]

print "Got %d families" % (len(families))

family_graph = []
for f in families:
    tmp_nodes = []
    fam_node = dict()
    fam_node["nodes"] = tmp_nodes
    for sample in f["samples"]:
        if sample["id"] in G.nodes():
            fam_node["nodes"].append(sample["id"])
            try:
                nodes.remove(sample["id"])
            except:
                print "Sample is already removed, maybe another family"

    coverage = float(len(fam_node["nodes"])) / len(f["samples"]) * 100
    print "Family got %d nodes ( %f %% coverage ) " % (len(fam_node["nodes"]),
                                                       coverage)
    color = random.random()
    fam_node["color"] = [color*10 for i in xrange(len(fam_node["nodes"]))]
    family_graph.append(fam_node)


limits = plt.axis('off')
layout = nx.drawing.nx_agraph.pygraphviz_layout(G, prog="fdp")

nx.draw_networkx_nodes(G, layout, node_list=nodes, node_shape='.')

for f in family_graph:
    color = [(random.random(), random.random(), random.random())]*len(f["nodes"])
    nx.draw_networkx_nodes(G, layout, nodelist=f["nodes"], node_color=color)

nx.draw_networkx_edges(G, layout)
nx.draw_networkx_labels(G, layout, labels=nodes_label)

nx.drawing.nx_agraph.write_dot(G, "machoc_families.dot")
fig = matplotlib.pyplot.gcf()
fig.set_size_inches(200, 200)
limits = plt.axis('off')
ax = fig.gca()
ax.set_axis_off()
ax.autoscale(True)
plt.savefig("machoc_clusters.svg")
