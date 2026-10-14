"""
Detection Chain Visualisation (optional)
MITRE ATT&CK Rule-Based Navigator

Owner: Sivaranjanii M

Draws the forward-chaining result as a left-to-right diagram:

    observed facts  ->  rule that fired  ->  technique concluded  ->  next rule ...

A technique that feeds another rule (e.g. T1059.001 -> R018) is drawn
as a link between the two, so chained reasoning is visible at a glance.
Near-miss rules are shown with dashed outlines and the facts they did match.

Needs matplotlib (pip install matplotlib). The rest of the system works
without it; the menu simply reports that the chart is unavailable.
"""

import os
import textwrap

SEVERITY_COLOUR = {          # border colour, with the label also naming it
    "high": "#d03b3b",
    "medium": "#ec835a",
    "low": "#fab219",
}
FACT_FILL = "#f2f2f0"
FACT_EDGE = "#8a8a85"
INK = "#1f1f1e"
MUTED = "#8a8a85"


def matplotlib_available():
    try:
        import matplotlib  # noqa: F401
        return True
    except ImportError:
        return False


def _wrap(text, width=30):
    return "\n".join(textwrap.wrap(text, width, break_long_words=True)) or text


def _layout(data):
    """
    Work out columns and rows.

    depth(rule) = 1 + deepest rule that produced one of its conditions
    Column of a rule = 2*depth - 1, its technique sits at 2*depth.
    Observed facts sit in column 0.
    """

    trace = data["trace"]
    depth = {}
    for entry in trace:                       # firing order: parents come first
        parents = [
            depth[c["source"]]
            for c in entry["matched_conditions"]
            if c["source"] != "observed" and c["source"] in depth
        ]
        depth[entry["rule_id"]] = 1 + (max(parents) if parents else 0)

    nodes = {}      # key -> dict(col, label, kind, severity)
    edges = []      # (from_key, to_key, dashed)
    fact_order = []

    def add_fact(fact):
        key = "fact:" + fact
        if key not in nodes:
            nodes[key] = {"col": 0, "label": _wrap(fact, 30), "kind": "fact"}
            fact_order.append(key)
        return key

    for entry in trace:
        rid = entry["rule_id"]
        d = depth[rid]
        rule_key = "rule:" + rid
        tech_key = "tech:" + entry["technique_id"]
        nodes[rule_key] = {"col": 2 * d - 1, "label": rid, "kind": "rule"}
        nodes[tech_key] = {
            "col": 2 * d,
            "label": f"{entry['technique_id']}\n{_wrap(entry['technique_name'], 24)}\n"
                     f"{entry['tactic']} | {entry['severity'].upper()}",
            "kind": "tech",
            "severity": entry["severity"],
        }
        for c in entry["matched_conditions"]:
            if c["source"] == "observed":
                edges.append((add_fact(c["fact"]), rule_key, False))
            else:
                parent_tech = "tech:" + c["fact"].split(":", 1)[1]
                edges.append((parent_tech, rule_key, False))
        edges.append((rule_key, tech_key, False))

    for n in data["near_misses"]:
        rule_key = "near:" + n["rule_id"]
        tech_key = "neartech:" + n["technique_id"]
        nodes[rule_key] = {"col": 1, "label": f"{n['rule_id']}\n{n['matched']}/{n['total']} met",
                           "kind": "near"}
        nodes[tech_key] = {
            "col": 2,
            "label": f"{n['technique_id']} (possible)\n{_wrap(n['technique_name'], 24)}\n"
                     f"confidence {n['confidence']:.2f}",
            "kind": "neartech",
        }
        for fact in n["present"]:
            if fact.startswith("technique_detected:"):
                edges.append(("tech:" + fact.split(":", 1)[1], rule_key, True))
            else:
                edges.append((add_fact(fact), rule_key, True))
        edges.append((rule_key, tech_key, True))

    # row positions: keep the insertion order inside each column
    columns = {}
    for key, node in nodes.items():
        columns.setdefault(node["col"], []).append(key)
    for col, keys in columns.items():
        for i, key in enumerate(keys):
            nodes[key]["row"] = i
            nodes[key]["rows_in_col"] = len(keys)

    return nodes, edges, columns


def draw_chain(data, path=None, show=False):
    """
    Draw the detection chain. Saves a PNG when path is given and opens a
    window when show is True. Returns the saved path (or None).
    """

    if not data["trace"] and not data["near_misses"]:
        raise ValueError("Nothing to draw: no rule fired and there are no near misses.")

    import matplotlib
    if not show:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    nodes, edges, columns = _layout(data)
    n_cols = max(columns) + 1
    tallest = max(len(v) for v in columns.values())

    fig_w = max(8.0, 3.3 * n_cols)
    fig_h = max(3.5, 0.95 * tallest + 1.6)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_xlim(-0.6, n_cols - 0.4)
    ax.set_ylim(-0.8, tallest - 0.2)
    ax.axis("off")

    texts = {}
    for key, node in nodes.items():
        # centre each column vertically
        offset = (tallest - node["rows_in_col"]) / 2
        y = tallest - 1 - (node["row"] + offset)
        x = node["col"]
        kind = node["kind"]

        style = dict(boxstyle="round,pad=0.45", linewidth=1.2)
        colour = INK
        if kind == "fact":
            style.update(facecolor=FACT_FILL, edgecolor=FACT_EDGE)
        elif kind == "rule":
            style.update(facecolor="white", edgecolor=INK)
        elif kind == "tech":
            style.update(facecolor="white", edgecolor=SEVERITY_COLOUR.get(node["severity"], INK),
                         linewidth=2.4)
        else:  # near-miss rule or technique
            style.update(facecolor="white", edgecolor=MUTED, linestyle="--")
            colour = MUTED

        texts[key] = ax.text(
            x, y, node["label"], ha="center", va="center", fontsize=8,
            color=colour, bbox=style, zorder=3,
            fontweight="bold" if kind in ("rule", "tech") else "normal",
        )

    # draw arrows edge-to-edge using the rendered box sizes
    # (layout is fixed first so the measured positions stay valid)
    fig.tight_layout()
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    inv = ax.transData.inverted()

    def box(key):
        patch = texts[key].get_bbox_patch()
        bb = patch.get_window_extent(renderer)
        (x0, y0), (x1, y1) = inv.transform([(bb.x0, bb.y0), (bb.x1, bb.y1)])
        return x0, x1, (y0 + y1) / 2

    for src, dst, dashed in edges:
        if src not in texts or dst not in texts:
            continue
        _, sx1, sy = box(src)
        dx0, _, dy = box(dst)
        ax.annotate(
            "", xy=(dx0, dy), xytext=(sx1, sy),
            arrowprops=dict(
                arrowstyle="-|>", color=MUTED if dashed else INK,
                linewidth=1.0, linestyle="--" if dashed else "-",
                shrinkA=0, shrinkB=0, connectionstyle="arc3,rad=0.0",
            ),
            zorder=2,
        )

    # column headings
    headings = {0: "Observed facts"}
    for col in range(1, n_cols):
        headings[col] = "Rule" if col % 2 else "Technique"
    for col, title in headings.items():
        ax.text(col, tallest - 0.35, title, ha="center", va="bottom",
                fontsize=9, color=MUTED, fontweight="bold")

    ax.set_title(f"Detection chain: {data['source']}", fontsize=12, color=INK, loc="left")
    ax.text(
        -0.6, -0.75,
        "Solid = rule fired (forward chaining).  Dashed = near miss, rule did not fire.  "
        "Technique border colour = severity (also printed in the box).",
        fontsize=7.5, color=MUTED, ha="left", va="bottom",
    )

    saved = None
    if path:
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        fig.savefig(path, dpi=150, bbox_inches="tight")
        saved = path
    if show:
        plt.show()
    plt.close(fig)
    return saved
