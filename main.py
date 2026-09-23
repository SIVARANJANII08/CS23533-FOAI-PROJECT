"""
MITRE ATT&CK Rule-Based Navigator
Entry point. Run with:  python main.py
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from knowledge_base import KnowledgeBase, Fact
from inference_engine import ForwardChainingEngine
from explanation import ExplanationBuilder


def main():
    print("=" * 60)
    print("  MITRE ATT&CK Rule-Based Navigator")
    print("=" * 60)

    kb = KnowledgeBase()
    kb.load_rules("data/rules.json")
    kb.load_mitigations("data/mitigations.json")
    print("\n" + kb.summary() + "\n")

    # Sample observed behaviours - Module 4 will read these from a log file
    observations = [
        Fact.from_string("process_created:powershell.exe"),
        Fact.from_string("command_line_contains:-EncodedCommand"),
        Fact.from_string("parent_process:winword.exe"),
        Fact.from_string("failed_login_count_exceeds:5"),
        Fact.from_string("same_source_ip:true"),
    ]

    print("Observed behaviours:")
    for obs in observations:
        print(f"  - {obs}")

    # ---- Module 2: forward chaining ----
    engine = ForwardChainingEngine(kb)
    engine.assert_observations(observations)
    engine.run()

    explainer = ExplanationBuilder(engine)

    print("\n--- Inference trace (rules in firing order) ---")
    for entry in engine.get_trace():
        print(f"  {entry['order']}. cycle {entry['cycle']}: {entry['rule_id']} fired "
              f"-> {', '.join(entry['conclusions'])}")

    print("\n" + explainer.run_summary())

    print("\n--- WHY: explanation for each detected technique ---\n")
    print(explainer.explain_all())

    print("\n--- Recommended mitigations ---")
    for rule in engine.detected_techniques():
        for mid in rule.mitigation_ids:
            print(f"  {rule.technique_id}: {mid} {kb.get_mitigation(mid)['name']}")

    print("\n--- WHY NOT: near misses ---\n")
    print(explainer.why_not("T1110.001"))
    print()


if __name__ == "__main__":
    main()