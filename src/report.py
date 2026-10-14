"""
Report Output Format
MITRE ATT&CK Rule-Based Navigator

Owner: Sivaranjanii M

Builds the detection report shown at the end of a run. The report is
plain ASCII so it prints the same in PowerShell, Command Prompt and a
saved .txt file.

Two steps, kept separate so the chart and the saved file use exactly
the same numbers as the console:

    data = collect(agent, knowledge_base, parse_result)   # facts only
    text = render(data)                                   # formatting only
"""

import textwrap
from datetime import datetime

try:
    from .input_parser import ParseResult
except ImportError:
    from input_parser import ParseResult


SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

# ATT&CK enterprise tactic order, used to print tactics as a kill chain
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

TEAM_DEFINED_MITIGATIONS = {"M9001"}

LINE_WIDTH = 100


# ----------------------------------------------------------------------
# 1. Collect: pull everything the report needs out of the agent
# ----------------------------------------------------------------------

def collect(agent, knowledge_base, parse_result=None):
    """Return a plain dict describing one completed run."""

    engine = agent.engine

    if parse_result is None:
        parse_result = ParseResult("not recorded")

    # rules that fired, ranked by confidence then severity
    # (stable sort, so equal rules stay in firing order)
    detected_rules = agent.get_results()
    ranked_detected = engine.rank_rules(detected_rules)
    cycle_of = {e["rule_id"]: e["cycle"] for e in engine.get_trace()}

    detected = [
        {
            "rule_id": r.rule_id,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "severity": r.severity,
            "confidence": engine.heuristic(r),
            "cycle": cycle_of.get(r.rule_id),
            "mitigation_ids": list(r.mitigation_ids),
        }
        for r in ranked_detected
    ]

    # near misses: partly matched, never fired
    near_misses = []
    for r in agent.get_ranked_rules():
        score = engine.heuristic(r)
        if 0.0 < score < 1.0:
            info = engine.partial_matches.get(r.rule_id, {})
            near_misses.append({
                "rule_id": r.rule_id,
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "tactic": r.tactic,
                "severity": r.severity,
                "confidence": score,
                "matched": info.get("matched_count", 0),
                "total": info.get("total_conditions", len(r.conditions)),
                "present": [str(f) for f in info.get("matched_conditions", [])],
                "missing": [str(f) for f in info.get("unmatched_conditions", [])],
            })

    # mitigations, merged across techniques
    mitigations = {}
    for d in detected:
        for mid in d["mitigation_ids"]:
            entry = mitigations.setdefault(mid, {
                "id": mid,
                "name": knowledge_base.get_mitigation(mid)["name"],
                "techniques": [],
                "team_defined": mid in TEAM_DEFINED_MITIGATIONS,
            })
            entry["techniques"].append(d["technique_id"])

    # which rules used each observed fact
    used_by = {}
    for r in knowledge_base.rules:
        for c in r.conditions:
            used_by.setdefault(str(c), []).append(r.rule_id)

    fired = {d["rule_id"] for d in detected}
    observed = []
    for i, fact in enumerate(parse_result.facts, start=1):
        key = str(fact)
        lines = parse_result.origins.get(key, [])
        observed.append({
            "n": i,
            "fact": key,
            "lines": lines,
            "rules": used_by.get(key, []),
            "fired_rules": [r for r in used_by.get(key, []) if r in fired],
        })

    tactics = sorted(
        {d["tactic"] for d in detected},
        key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99,
    )

    severity_counts = {s: 0 for s in ("high", "medium", "low")}
    for d in detected:
        severity_counts[d["severity"]] = severity_counts.get(d["severity"], 0) + 1

    observed_count = sum(1 for s in engine.fact_source.values() if s == "observed")

    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "source": parse_result.source,
        "lines_read": parse_result.lines_read,
        "warnings": list(parse_result.warnings),
        "no_fact_lines": list(getattr(parse_result, "no_facts", [])),
        "kb_summary": knowledge_base.summary(),
        "observed": observed,
        "detected": detected,
        "tactics": tactics,
        "severity_counts": severity_counts,
        "trace": engine.get_trace(),
        "explanation": agent.get_explanation(),
        "mitigations": list(mitigations.values()),
        "near_misses": near_misses,
        "cycles": engine.cycles,
        "termination_reason": engine.termination_reason,
        "facts_observed": observed_count,
        "facts_derived": len(engine.fact_source) - observed_count,
    }


# ----------------------------------------------------------------------
# 2. Render: ASCII tables
# ----------------------------------------------------------------------

def ascii_table(headers, rows, widths):
    """
    Draw a table with +---+ borders. Long cells wrap inside their column.
    widths gives the maximum width of each column.
    """

    # shrink columns to fit their content
    cols = []
    for i, h in enumerate(headers):
        longest = max([len(h)] + [len(str(r[i])) for r in rows]) if rows else len(h)
        cols.append(max(len(h), min(widths[i], longest)))

    border = "+" + "+".join("-" * (w + 2) for w in cols) + "+"

    def emit(cells):
        wrapped = [
            textwrap.wrap(str(c), w, break_long_words=True, break_on_hyphens=False) or [""]
            for c, w in zip(cells, cols)
        ]
        height = max(len(x) for x in wrapped)
        out = []
        for line in range(height):
            parts = [
                (wrapped[i][line] if line < len(wrapped[i]) else "").ljust(cols[i])
                for i in range(len(cols))
            ]
            out.append("| " + " | ".join(parts) + " |")
        return out

    lines = [border] + emit(headers) + [border.replace("-", "=")]
    for r in rows:
        lines += emit(r)
    lines.append(border)
    return lines


def _section(number, title):
    return ["", f"[{number}] {title}", "-" * LINE_WIDTH]


def _lines_label(lines):
    if not lines:
        return "-"
    if len(lines) > 4:
        return f"lines {lines[0]}-{lines[-1]} ({len(lines)})"
    return "line " + ", ".join(str(n) for n in lines)


def render(data):
    """Turn collected data into the report text."""

    out = []
    bar = "=" * LINE_WIDTH

    out += [
        bar,
        "  MITRE ATT&CK RULE-BASED NAVIGATOR  -  DETECTION REPORT",
        bar,
        f"  Input       : {data['source']}  "
        f"({data['lines_read']} lines read, {len(data['observed'])} facts)",
        f"  Generated   : {data['generated']}",
        f"  Knowledge   : {data['kb_summary']}",
    ]

    # [1] summary ------------------------------------------------------
    sc = data["severity_counts"]
    top = next(
        (s.upper() for s in ("high", "medium", "low") if sc.get(s)), "NONE"
    )
    out += _section(1, "SUMMARY")
    out += [
        f"  Techniques detected : {len(data['detected'])}"
        f"   (high {sc['high']}, medium {sc['medium']}, low {sc['low']})",
        f"  Highest severity    : {top}",
        "  Tactics reached     : "
        + (" -> ".join(data["tactics"]) if data["tactics"] else "none"),
        f"  Possible techniques : {len(data['near_misses'])} near miss(es)",
        f"  Inference           : {data['cycles']} cycle(s), "
        f"{data['facts_observed']} observed + {data['facts_derived']} derived facts, "
        f"stopped by {data['termination_reason']}",
    ]

    # [2] observed facts ----------------------------------------------
    out += _section(2, "OBSERVED FACTS  (what went into working memory)")
    rows = [
        [
            o["n"],
            o["fact"],
            _lines_label(o["lines"]),
            ", ".join(o["rules"]) if o["rules"] else "(no rule)",
        ]
        for o in data["observed"]
    ]
    if rows:
        out += ascii_table(["#", "Fact", "From", "Condition of"], rows, [3, 52, 18, 18])
    else:
        out.append("  No facts were provided.")

    # [3] detected techniques -----------------------------------------
    out += _section(3, "DETECTED TECHNIQUES  (ranked by confidence, then severity)")
    rows = [
        [
            i,
            d["technique_id"],
            d["technique_name"],
            d["tactic"],
            d["severity"].upper(),
            f"{d['confidence']:.2f}",
            d["rule_id"],
        ]
        for i, d in enumerate(data["detected"], start=1)
    ]
    if rows:
        out += ascii_table(
            ["Rank", "Technique", "Name", "Tactic", "Severity", "Conf.", "Rule"],
            rows, [4, 10, 34, 17, 8, 5, 4],
        )
    else:
        out.append("  No techniques detected. No rule had all of its conditions met.")

    # [4] detection chain ---------------------------------------------
    out += _section(4, "DETECTION CHAIN  (rules in the order they fired)")
    rows = []
    for e in data["trace"]:
        conditions = "; ".join(
            c["fact"] + ("" if c["source"] == "observed" else f" [from {c['source']}]")
            for c in e["matched_conditions"]
        )
        rows.append([e["order"], e["cycle"], e["rule_id"], conditions,
                     ", ".join(e["conclusions"])])
    if rows:
        out += ascii_table(
            ["Step", "Cycle", "Rule", "IF (all conditions present)", "THEN (asserted)"],
            rows, [4, 5, 4, 40, 30],
        )
    else:
        out.append("  No rule fired.")

    # [5] why --------------------------------------------------------
    out += _section(5, "WHY  (reasoning behind each detection)")
    if data["trace"]:
        out += [("  " + line).rstrip() for line in data["explanation"].splitlines()]
    else:
        out.append("  Nothing to explain: no technique was concluded.")

    # [6] mitigations -------------------------------------------------
    out += _section(6, "RECOMMENDED MITIGATIONS")
    rows = [
        [m["id"] + (" *" if m["team_defined"] else ""), m["name"], ", ".join(m["techniques"])]
        for m in data["mitigations"]
    ]
    if rows:
        out += ascii_table(["ID", "Mitigation", "Addresses"], rows, [8, 42, 30])
        if any(m["team_defined"] for m in data["mitigations"]):
            out.append("  * M9001 is team-defined, not an official ATT&CK mitigation "
                       "(Discovery has no preventive mitigations).")
    else:
        out.append("  None - no technique was detected.")

    # [7] near misses -------------------------------------------------
    out += _section(7, "NEAR-MISS / POSSIBLE TECHNIQUES  (some conditions matched, rule did not fire)")
    rows = [
        [
            n["technique_id"],
            n["technique_name"],
            n["severity"].upper(),
            f"{n['confidence']:.2f}",
            f"{n['matched']}/{n['total']}",
            "; ".join(n["missing"]),
        ]
        for n in data["near_misses"]
    ]
    if rows:
        out += ascii_table(
            ["Technique", "Name", "Severity", "Conf.", "Match", "Missing to fire"],
            rows, [10, 26, 8, 5, 5, 30],
        )
        out.append("  Confidence = matched conditions / total conditions (Module 3 heuristic).")
    else:
        out.append("  None.")

    # [8] input notes --------------------------------------------------
    if data["warnings"] or data["no_fact_lines"]:
        out += _section(8, "INPUT NOTES")
        for w in data["warnings"]:
            out.append(f"  ! {w}")
        if data["no_fact_lines"]:
            out.append(
                f"  - {len(data['no_fact_lines'])} event(s) produced no facts "
                f"(ordinary activity): {_lines_label(data['no_fact_lines'])}"
            )

    out += ["", bar, "  END OF REPORT", bar]
    return "\n".join(out)


def save(text, path):
    """Write the report to a text file."""

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    return path
