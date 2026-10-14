"""
MITRE ATT&CK Rule-Based Navigator - Web Interface
Owner: Sivaranjanii M

A local website in front of the same rule-based engine the CLI uses.
Nothing about the reasoning changes: the pages call the existing
input parser, agent, explanation builder and report collector.

Run:
    pip install flask
    python app.py
Then open http://127.0.0.1:5000 in a browser.
"""

import os
import sys
import uuid

from flask import Flask, render_template, request, url_for

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(ROOT, "src"))

from knowledge_base import KnowledgeBase                      # noqa: E402
from input_parser import (                                    # noqa: E402
    parse_file, parse_fact_lines, parse_log_lines,
    list_samples, describe_sample, FACT_EXTENSIONS, LOG_EXTENSIONS,
)
from cli import analyse                                       # noqa: E402
import visualize                                              # noqa: E402

SAMPLES_DIR = os.path.join(ROOT, "samples")
CHART_DIR = os.path.join(ROOT, "static", "charts")
MAX_CHARTS_KEPT = 30

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024   # 1 MB upload limit


def load_kb():
    kb = KnowledgeBase()
    kb.load_rules(os.path.join(ROOT, "data", "rules.json"))
    kb.load_mitigations(os.path.join(ROOT, "data", "mitigations.json"))
    return kb


KB = load_kb()


def samples():
    return [
        {"name": os.path.basename(p), "description": describe_sample(p)}
        for p in list_samples(SAMPLES_DIR)
    ]


def techniques():
    """Every technique in the knowledge base, for the why-not dropdown."""
    return [
        {"id": r.technique_id, "name": r.technique_name, "rule": r.rule_id}
        for r in KB.rules
    ]


def _tidy_old_charts():
    """Keep the charts folder small: delete the oldest images."""
    if not os.path.isdir(CHART_DIR):
        return
    files = sorted(
        (os.path.join(CHART_DIR, f) for f in os.listdir(CHART_DIR) if f.endswith(".png")),
        key=os.path.getmtime,
    )
    for path in files[:-MAX_CHARTS_KEPT]:
        try:
            os.remove(path)
        except OSError:
            pass


def _make_chart(data):
    if not visualize.matplotlib_available():
        return None, "matplotlib is not installed, so the chart is skipped (pip install matplotlib)."
    if not data["trace"] and not data["near_misses"]:
        return None, "No chart: no rule fired and there are no near misses."
    os.makedirs(CHART_DIR, exist_ok=True)
    _tidy_old_charts()
    name = f"chain_{uuid.uuid4().hex[:10]}.png"
    visualize.draw_chain(data, os.path.join(CHART_DIR, name))
    return url_for("static", filename=f"charts/{name}"), None


def _read_input(form, files):
    """
    Work out which input the user gave and parse it.
    Returns (ParseResult, error message or None).
    """
    mode = form.get("mode", "sample")

    if mode == "sample":
        name = form.get("sample", "")
        allowed = {s["name"] for s in samples()}
        if name not in allowed:
            return None, "Please choose one of the sample scenarios."
        return parse_file(os.path.join(SAMPLES_DIR, name), KB), None

    if mode == "manual":
        text = form.get("facts", "")
        lines = text.splitlines()
        if not any(l.strip() and not l.strip().startswith("#") for l in lines):
            return None, "Type at least one fact, for example process_created:powershell.exe"
        return parse_fact_lines(lines, source="manual entry", knowledge_base=KB), None

    if mode == "upload":
        upload = files.get("upload")
        if upload is None or not upload.filename:
            return None, "Choose a file to upload."
        ext = os.path.splitext(upload.filename)[1].lower()
        try:
            lines = upload.read().decode("utf-8-sig").splitlines()
        except UnicodeDecodeError:
            return None, "The file is not plain text (UTF-8)."
        name = os.path.basename(upload.filename)
        if ext in LOG_EXTENSIONS:
            return parse_log_lines(lines, source=name, knowledge_base=KB), None
        if ext in FACT_EXTENSIONS:
            return parse_fact_lines(lines, source=name, knowledge_base=KB), None
        return None, f"Unsupported file type '{ext}'. Use .log, .facts or .txt"

    if mode == "rerun":
        # used by the why-not form: the facts from the last run come back
        result = parse_fact_lines(
            form.get("facts", "").splitlines(),
            source=form.get("source", "previous run"),
            knowledge_base=KB,
        )
        for key in result.origins:          # line numbers no longer apply
            result.origins[key] = []
        return result, None

    return None, "Unknown input type."


# ----------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template(
        "index.html", samples=samples(), kb_summary=KB.summary(), error=None, form={},
    )


@app.route("/analyse", methods=["POST"])
def analyse_page():
    result, error = _read_input(request.form, request.files)
    if error:
        return render_template(
            "index.html", samples=samples(), kb_summary=KB.summary(),
            error=error, form=request.form,
        ), 400

    agent, data = analyse(KB, result)
    chart_url, chart_note = _make_chart(data)

    # optional "why not?" question
    question = request.form.get("why_not", "").strip().upper()
    answer = None
    if question:
        detected = {d["technique_id"] for d in data["detected"]}
        answer = (agent.explainer.explain(question) if question in detected
                  else agent.explainer.why_not(question))

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    top = min((d["severity"] for d in data["detected"]),
              key=lambda s: severity_rank.get(s, 9), default="none")

    return render_template(
        "result.html",
        data=data,
        top_severity=top,
        chart_url=chart_url,
        chart_note=chart_note,
        fact_text="\n".join(o["fact"] for o in data["observed"]),
        techniques=techniques(),
        question=question,
        answer=answer,
        run_summary=agent.explainer.run_summary(),
    )


@app.route("/rules")
def rules_page():
    return render_template("rules.html", rules=KB.rules, kb=KB)


@app.errorhandler(413)
def too_large(_):
    return render_template(
        "index.html", samples=samples(), kb_summary=KB.summary(),
        error="That file is larger than 1 MB.", form={},
    ), 413


if __name__ == "__main__":
    print("\n  MITRE ATT&CK Rule-Based Navigator - website")
    print("  Open http://127.0.0.1:5000 in your browser. Press Ctrl+C to stop.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
