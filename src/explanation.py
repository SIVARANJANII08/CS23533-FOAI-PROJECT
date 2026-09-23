"""
Module 2 (part 2): Explanation Trace
MITRE ATT&CK Rule-Based Navigator

Owner: Sivaranjanii M

Answers two questions an analyst (or examiner) will ask:
    WHY     was a technique concluded?  -> the chain of rules and facts
    WHY NOT was a technique concluded?  -> which conditions were missing

Works purely from the engine's trace and fact provenance, so every
line of an explanation points back to a rule in rules.json or a fact
that was actually observed.
"""


class ExplanationBuilder:

    def __init__(self, engine):
        self.engine = engine

    # -- helpers --------------------------------------------------------

    def _entry_for_technique(self, technique_id):
        for entry in self.engine.get_trace():
            if entry["technique_id"] == technique_id:
                return entry
        return None

    def _entry_for_rule(self, rule_id):
        for entry in self.engine.get_trace():
            if entry["rule_id"] == rule_id:
                return entry
        return None

    # -- WHY --------------------------------------------------------------

    def explain(self, technique_id, _depth=0, _seen=None):
        """
        Return the reasoning chain for one concluded technique as text.
        Derived conditions are expanded recursively, so a multi-step
        chain shows every rule back to the original observations.
        """

        seen = _seen if _seen is not None else set()
        pad = "    " * _depth
        entry = self._entry_for_technique(technique_id)

        if entry is None:
            return f"{pad}{technique_id} was NOT concluded. See why_not()."

        lines = [
            f"{pad}{entry['technique_id']} - {entry['technique_name']}",
            f"{pad}  concluded by rule {entry['rule_id']} "
            f"(cycle {entry['cycle']}, tactic: {entry['tactic']}, "
            f"severity: {entry['severity']})",
            f"{pad}  because ALL of these facts were in working memory:",
        ]

        seen.add(entry["rule_id"])

        for cond in entry["matched_conditions"]:
            if cond["source"] == "observed":
                lines.append(f"{pad}    [observed] {cond['fact']}")
                continue

            lines.append(
                f"{pad}    [derived by {cond['source']}] {cond['fact']}"
            )

            parent = self._entry_for_rule(cond["source"])
            if parent and parent["rule_id"] not in seen:
                lines.append(
                    self.explain(parent["technique_id"], _depth + 2, seen)
                )

        return "\n".join(lines)

    def explain_all(self):
        """Explanations for every technique, in the order rules fired."""

        return "\n\n".join(
            self.explain(entry["technique_id"])
            for entry in self.engine.get_trace()
        )

    # -- WHY NOT ------------------------------------------------------

    def why_not(self, technique_id):
        """
        Explain why a technique was NOT concluded, using the partial
        match data recorded by the match phase.
        """

        rule = next(
            (r for r in self.engine.knowledge_base.rules
             if r.technique_id == technique_id),
            None,
        )

        if rule is None:
            return f"{technique_id} is not in the knowledge base."

        if self._entry_for_technique(technique_id):
            return f"{technique_id} WAS concluded. See explain()."

        info = self.engine.partial_matches.get(rule.rule_id)
        if info is None:
            return f"{rule.rule_id} was never evaluated."

        lines = [
            f"{technique_id} - {rule.technique_name} was NOT concluded.",
            f"  Rule {rule.rule_id} matched "
            f"{info['matched_count']}/{info['total_conditions']} conditions.",
        ]
        for fact in info["matched_conditions"]:
            lines.append(f"    [present] {fact}")
        for fact in info["unmatched_conditions"]:
            lines.append(f"    [MISSING] {fact}")

        return "\n".join(lines)

    # -- RUN SUMMARY -------------------------------------------------

    def run_summary(self):
        e = self.engine
        observed = sum(1 for s in e.fact_source.values() if s == "observed")
        derived = len(e.fact_source) - observed
        return (
            f"Cycles run: {e.cycles} | Rules fired: {len(e.trace)} | "
            f"Facts: {observed} observed + {derived} derived | "
            f"Stopped by: {e.termination_reason}"
        )