"""
Test file for Module 2 + Module 3
MITRE ATT&CK Rule-Based Navigator

Module 2:
- Working Memory
- Rule matching
- Conflict set
- Forward chaining

Module 3:
- Heuristic calculation
- Best-first rule selection
- Tie-breaking
- Confidence-ranked output
- Near-miss / possible technique reporting
"""


try:
    from .knowledge_base import KnowledgeBase, Fact
    from .inference_engine import ForwardChainingEngine
except ImportError:
    from knowledge_base import KnowledgeBase, Fact
    from inference_engine import ForwardChainingEngine


def main():

    print("=" * 60)
    print("   MODULE 2 + MODULE 3 INFERENCE ENGINE TEST")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. LOAD KNOWLEDGE BASE
    # ---------------------------------------------------------

    kb = KnowledgeBase()

    kb.load_rules("data/rules.json")

    print("\nKnowledge Base loaded successfully.")
    print(kb.summary())

    # ---------------------------------------------------------
    # 2. CREATE OBSERVED FACTS
    # ---------------------------------------------------------

    observations = [
        Fact.from_string("process_created:cmd.exe"),
        Fact.from_string("command_line_contains:/c"),
        Fact.from_string("parent_process_unusual:true"),
        Fact.from_string("command_line_contains:dir /s"),
        Fact.from_string("recursive_enumeration:true"),
    ]

    print("\nObserved facts:")

    for fact in observations:
        print(f"  {fact}")

    # ---------------------------------------------------------
    # 3. CREATE ENGINE
    # ---------------------------------------------------------

    engine = ForwardChainingEngine(kb)

    # ---------------------------------------------------------
    # 4. ASSERT OBSERVATIONS
    # ---------------------------------------------------------

    added = engine.assert_observations(observations)

    print(f"\nFacts added to working memory: {added}")

    # ---------------------------------------------------------
    # 5. MODULE 3 - HEURISTIC SCORES
    # ---------------------------------------------------------

    print("\n--- Module 3: Rule Heuristic Scores ---")

    for rule in kb.rules:

        score = engine.heuristic(rule)

        print(
            f"{rule.rule_id} | "
            f"{rule.technique_id} | "
            f"severity={rule.severity} | "
            f"heuristic={score:.2f}"
        )

    # ---------------------------------------------------------
    # 6. BUILD CONFLICT SET
    # ---------------------------------------------------------

    conflict_set = engine.build_conflict_set()

    print("\n--- Conflict Set ---")

    if not conflict_set:

        print("No rules are currently fully matched.")

    else:

        for rule in conflict_set:

            print(
                f"{rule.rule_id} | "
                f"{rule.technique_id} | "
                f"severity={rule.severity} | "
                f"score={engine.heuristic(rule):.2f}"
            )

    # ---------------------------------------------------------
    # 7. MODULE 3 - CONFIDENCE-RANKED RULES
    # ---------------------------------------------------------

    print("\n--- Confidence-Ranked Rules ---")

    ranked_rules = engine.rank_rules()

    for rule in ranked_rules:

        print(
            f"{rule.rule_id} | "
            f"{rule.technique_id} | "
            f"confidence={engine.heuristic(rule):.2f} | "
            f"severity={rule.severity}"
        )

    # ---------------------------------------------------------
    # 8. MODULE 3 - BEST-FIRST SELECTION
    # ---------------------------------------------------------

    if conflict_set:

        selected_rule = engine.select_rule(conflict_set)

        print("\n--- Module 3 Best-First Selection ---")

        print(
            f"Selected rule: {selected_rule.rule_id}"
        )

        print(
            f"Technique: {selected_rule.technique_id} - "
            f"{selected_rule.technique_name}"
        )

        print(
            f"Severity: {selected_rule.severity}"
        )

        print(
            f"Heuristic score: "
            f"{engine.heuristic(selected_rule):.2f}"
        )

    # ---------------------------------------------------------
    # 9. MODULE 3 - NEAR-MISS / POSSIBLE TECHNIQUES
    # ---------------------------------------------------------

    print("\n--- Near-Miss / Possible Techniques ---")

    near_misses = [
        rule
        for rule in ranked_rules
        if 0.0 < engine.heuristic(rule) < 1.0
    ]

    if not near_misses:

        print("No near-miss rules found.")

    else:

        for rule in near_misses:

            score = engine.heuristic(rule)

            matched = engine.partial_matches.get(
                rule.rule_id,
                {}
            ).get("matched_count", 0)

            total = engine.partial_matches.get(
                rule.rule_id,
                {}
            ).get("total_conditions", len(rule.conditions))

            print(
                f"{rule.rule_id} | "
                f"{rule.technique_id} | "
                f"confidence={score:.2f} | "
                f"matched={matched}/{total} | "
                f"severity={rule.severity}"
            )

    # ---------------------------------------------------------
    # 10. RUN FORWARD CHAINING
    # ---------------------------------------------------------

    print("\n--- Running Forward Chaining ---")

    final_memory = engine.run()

    print("\nInference completed.")

    # ---------------------------------------------------------
    # 11. DISPLAY DETECTED TECHNIQUES
    # ---------------------------------------------------------

    print("\n--- Detected Techniques ---")

    detected = engine.detected_techniques()

    if not detected:

        print("No techniques detected.")

    else:

        for rule in detected:

            print(
                f"{rule.technique_id} - "
                f"{rule.technique_name}"
            )

    # ---------------------------------------------------------
    # 12. DISPLAY INFERENCE TRACE
    # ---------------------------------------------------------

    print("\n--- Inference Trace ---")

    for step in engine.get_trace():

        print(
            f"\nStep {step['order']}: "
            f"Rule {step['rule_id']} fired"
        )

        print(
            f"  Technique: "
            f"{step['technique_id']} - "
            f"{step['technique_name']}"
        )

        print(
            f"  Severity: {step['severity']}"
        )

        print(
            f"  Cycle: {step['cycle']}"
        )

        print(
            f"  Matched conditions: "
            f"{step['matched_count']}/"
            f"{step['total_conditions']}"
        )

        print(
            f"  Conclusions: "
            f"{', '.join(step['conclusions'])}"
        )

    # ---------------------------------------------------------
    # 13. DISPLAY PARTIAL MATCH TRACKING
    # ---------------------------------------------------------

    print("\n--- Partial-Match Tracking ---")

    for rule_id, info in engine.partial_matches.items():

        print(
            f"{rule_id}: "
            f"{info['matched_count']}/"
            f"{info['total_conditions']} "
            f"conditions matched "
            f"(fully matched: "
            f"{info['fully_matched']})"
        )

    # ---------------------------------------------------------
    # 14. TERMINATION INFORMATION
    # ---------------------------------------------------------

    print("\n--- Termination ---")

    print(
        f"Inference terminated: "
        f"{engine.terminated}"
    )

    print(
        f"Cycles completed: "
        f"{engine.cycles}"
    )

    print(
        f"Termination reason: "
        f"{engine.termination_reason}"
    )

    # ---------------------------------------------------------
    # 15. FINAL WORKING MEMORY
    # ---------------------------------------------------------

    print("\n--- Final Working Memory ---")

    for fact in sorted(
        final_memory,
        key=str
    ):

        print(f"  {fact}")

    print("\n" + "=" * 60)
    print("   TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()