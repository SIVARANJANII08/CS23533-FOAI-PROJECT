"""
MITRE ATT&CK Rule-Based Navigator
Module 4: Agent / Orchestration

Entry point. Run with:
    python main.py
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from knowledge_base import KnowledgeBase, Fact
from agent import Agent


def main():

    print("=" * 60)
    print("   MITRE ATT&CK Rule-Based Navigator")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. LOAD KNOWLEDGE BASE
    # ---------------------------------------------------------

    kb = KnowledgeBase()

    kb.load_rules("data/rules.json")
    kb.load_mitigations("data/mitigations.json")

    print("\n" + kb.summary() + "\n")

    # ---------------------------------------------------------
    # 2. CREATE OBSERVED BEHAVIOURS
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # 3. MODULE 4 - AGENT ORCHESTRATION
    # ---------------------------------------------------------

    agent = Agent(kb)

    engine = agent.process(observations)

    print("\nAgent processed the observations successfully.")

    # ---------------------------------------------------------
    # 4. CONFIDENCE-RANKED RESULTS
    # ---------------------------------------------------------

    print("\n--- Confidence-Ranked Rules ---")

    ranked_rules = agent.get_ranked_rules()

    for rule in ranked_rules:

        score = agent.engine.heuristic(rule)

        if score > 0:

            print(
                f"  {rule.rule_id} | "
                f"{rule.technique_id} | "
                f"confidence={score:.2f} | "
                f"severity={rule.severity}"
            )

    # ---------------------------------------------------------
    # 5. DETECTED TECHNIQUES
    # ---------------------------------------------------------

    print("\n--- Detected Techniques ---")

    detected = agent.get_results()

    if not detected:

        print("  No techniques detected.")

    else:

        for rule in detected:

            print(
                f"  {rule.technique_id} - "
                f"{rule.technique_name}"
            )

    # ---------------------------------------------------------
    # 6. INFERENCE TRACE
    # ---------------------------------------------------------

    print("\n--- Inference Trace ---")

    for entry in engine.get_trace():

        print(
            f"  {entry['order']}. "
            f"cycle {entry['cycle']}: "
            f"{entry['rule_id']} fired -> "
            f"{', '.join(entry['conclusions'])}"
        )

    # ---------------------------------------------------------
    # 7. EXPLANATIONS
    # ---------------------------------------------------------

    print("\n--- WHY: Explanation for Each Detected Technique ---\n")

    print(agent.get_explanation())

    # ---------------------------------------------------------
    # 8. RECOMMENDED MITIGATIONS
    # ---------------------------------------------------------

    print("\n--- Recommended Mitigations ---")

    mitigation_found = False

    for rule in detected:

        for mitigation_id in rule.mitigation_ids:

            mitigation = kb.get_mitigation(mitigation_id)

            if mitigation:

                print(
                    f"  {rule.technique_id}: "
                    f"{mitigation_id} "
                    f"{mitigation['name']}"
                )

                mitigation_found = True

    if not mitigation_found:

        print("  No mitigations available for detected techniques.")

    # ---------------------------------------------------------
    # 9. NEAR-MISS / POSSIBLE TECHNIQUES
    # ---------------------------------------------------------

    print("\n--- Near-Miss / Possible Techniques ---")

    near_misses = [
        rule
        for rule in ranked_rules
        if 0.0 < agent.engine.heuristic(rule) < 1.0
    ]

    if not near_misses:

        print("  No near-miss techniques found.")

    else:

        for rule in near_misses:

            score = agent.engine.heuristic(rule)

            info = engine.partial_matches.get(
                rule.rule_id,
                {}
            )

            matched = info.get(
                "matched_count",
                0
            )

            total = info.get(
                "total_conditions",
                len(rule.conditions)
            )

            print(
                f"  {rule.technique_id} | "
                f"confidence={score:.2f} | "
                f"matched={matched}/{total} | "
                f"severity={rule.severity}"
            )

    # ---------------------------------------------------------
    # 10. TERMINATION
    # ---------------------------------------------------------

    print("\n--- Inference Status ---")

    print(
        f"  Terminated: "
        f"{engine.terminated}"
    )

    print(
        f"  Cycles: "
        f"{engine.cycles}"
    )

    print(
        f"  Reason: "
        f"{engine.termination_reason}"
    )

    print("\n" + "=" * 60)
    print("   NAVIGATION COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()