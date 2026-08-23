"""
MITRE ATT&CK Rule-Based Navigator
Entry point. Run with:  python main.py
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from knowledge_base import KnowledgeBase, Fact


def main():
    print("=" * 60)
    print("  MITRE ATT&CK Rule-Based Navigator")
    print("=" * 60)

    kb = KnowledgeBase()
    kb.load_rules("data/rules.json")
    kb.load_mitigations("data/mitigations.json")
    print("\n" + kb.summary() + "\n")

    # Sample observed behaviours — Module 4 will read these from a log file
    observations = {
        Fact.from_string("process_created:powershell.exe"),
        Fact.from_string("command_line_contains:-EncodedCommand"),
        Fact.from_string("parent_process:winword.exe"),
        Fact.from_string("failed_login_count_exceeds:5"),
        Fact.from_string("same_source_ip:true"),
    }

    print("Observed behaviours:")
    for obs in sorted(observations, key=str):
        print(f"  - {obs}")

    print("\nRule evaluation (heuristic = matched / total conditions):\n")
    ranked = sorted(kb.rules, key=lambda r: r.heuristic(observations), reverse=True)

    for rule in ranked:
        score = rule.heuristic(observations)
        if score == 0:
            continue
        status = "DETECTED" if rule.is_fully_matched(observations) else "partial"
        print(f"  {score:.2f}  [{status:8}] {rule.technique_id} - {rule.technique_name}")

        if rule.is_fully_matched(observations):
            for mid in rule.mitigation_ids:
                m = kb.get_mitigation(mid)
                print(f"            Mitigation {mid}: {m['name']}")
    print()


if __name__ == "__main__":
    main()
