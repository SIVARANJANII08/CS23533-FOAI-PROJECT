"""
Module 2: Forward Chaining Inference Engine
MITRE ATT&CK Rule-Based Navigator

Match phase (WorkingMemory, match_rule, build_conflict_set): Pranathee H
Act phase (fire_rule, run, termination detection):         Sivaranjanii M
"""

try:
    from .knowledge_base import Fact, KnowledgeBase, Rule
except ImportError:
    from knowledge_base import Fact, KnowledgeBase, Rule


class WorkingMemory:
    """
    Stores facts currently known by the inference engine.

    A set is used so duplicate facts are automatically prevented.
    """

    def __init__(self):
        self.facts = set()

    def add(self, fact: Fact) -> bool:
        """
        Add a fact to working memory.

        Returns True if the fact was newly added,
        False if it was already present.
        """

        if fact in self.facts:
            return False

        self.facts.add(fact)
        return True

    def add_many(self, facts) -> int:
        """Add multiple facts and return the number of new facts added."""

        added_count = 0

        for fact in facts:
            if self.add(fact):
                added_count += 1

        return added_count

    def contains(self, fact: Fact) -> bool:
        """Check whether a fact is already in working memory."""

        return fact in self.facts

    def get_all(self):
        """Return all currently stored facts."""

        return set(self.facts)

    def clear(self) -> None:
        """Remove all facts from working memory."""

        self.facts.clear()

    def __len__(self):
        """Return the number of facts in working memory."""

        return len(self.facts)

    def __contains__(self, fact):
        """Allow: fact in working_memory."""

        return fact in self.facts

    def __iter__(self):
        """Allow iteration through working memory."""

        return iter(self.facts)


class ForwardChainingEngine:
    """
    Forward chaining inference engine.

    It matches the current working memory against the rules
    in the knowledge base and builds the conflict set.
    """

    def __init__(self, knowledge_base: KnowledgeBase):
        self.knowledge_base = knowledge_base
        self.working_memory = WorkingMemory()
        self.trace = []
        self.terminated = False
        self.partial_matches = {}

        # --- Act phase state (Sivaranjanii) ---
        self.fact_source = {}          # Fact -> "observed" or the rule_id that derived it
        self.fired_rules = set()       # refractoriness: a rule fires at most once
        self.cycles = 0                # recognize-act cycles completed
        self.termination_reason = None

    def match_rule(self, rule: Rule):
        """
        Match one rule against the current working memory.

        Returns information about matched and unmatched conditions.
        """

        matched = rule.matched_conditions(
            self.working_memory.facts
        )

        unmatched = [
            condition
            for condition in rule.conditions
            if condition not in self.working_memory.facts
        ]

        result = {
            "rule": rule,
            "matched_conditions": matched,
            "unmatched_conditions": unmatched,
            "matched_count": len(matched),
            "total_conditions": len(rule.conditions),
            "fully_matched": rule.is_fully_matched(
                self.working_memory.facts
            ),
        }

        self.partial_matches[rule.rule_id] = {
            "matched_count": result["matched_count"],
            "total_conditions": result["total_conditions"],
            "matched_conditions": result["matched_conditions"],
            "unmatched_conditions": result["unmatched_conditions"],
            "fully_matched": result["fully_matched"],
        }

        return result

    def build_conflict_set(self):
        """
        Build the conflict set.

        The conflict set contains all rules whose
        conditions are fully satisfied.
        """

        conflict_set = []

        for rule in self.knowledge_base.rules:
            result = self.match_rule(rule)

            if result["fully_matched"]:
                conflict_set.append(rule)

        return conflict_set
    # ------------------------------------------------------------------
    # ACT PHASE  (Sivaranjanii M)
    # ------------------------------------------------------------------

    def assert_observations(self, facts) -> int:
        """
        Load the observed behaviours into working memory before the
        engine runs. Each one is tagged "observed" so the explanation
        trace can tell raw evidence apart from derived conclusions.
        """

        added = 0

        for fact in facts:
            if self.working_memory.add(fact):
                self.fact_source[fact] = "observed"
                added += 1

        return added

    def select_rule(self, available_rules):
        """
        Conflict resolution: choose ONE rule from the eligible set.

        Current strategy: textual order (the order rules appear in
        rules.json). Module 3 replaces this method with best-first
        selection using the heuristic, without touching fire_rule/run.
        """

        return available_rules[0]

    def fire_rule(self, rule: Rule) -> list:
        """
        Fire a fully matched rule (the THEN part).

        Asserts two conclusions into working memory:
            technique_detected:<technique_id>
            tactic_detected:<tactic>
        and records the firing in the inference trace.

        Returns the list of facts that were NEW to working memory.
        A rule whose conclusions were already known still counts as
        fired (it is recorded and never re-fires), so the engine keeps
        going instead of stopping early.
        """

        if not rule.is_fully_matched(self.working_memory.facts):
            return []

        conclusions = [
            Fact("technique_detected", rule.technique_id),
            Fact("tactic_detected", rule.tactic),
        ]

        new_facts = []

        for fact in conclusions:
            if self.working_memory.add(fact):
                self.fact_source[fact] = rule.rule_id
                new_facts.append(fact)

        self.fired_rules.add(rule.rule_id)

        self.trace.append({
            "order": len(self.trace) + 1,
            "cycle": self.cycles + 1,
            "rule_id": rule.rule_id,
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic": rule.tactic,
            "severity": rule.severity,
            "matched_conditions": [
                {
                    "fact": str(condition),
                    "source": self.fact_source.get(condition, "observed"),
                }
                for condition in rule.conditions
            ],
            "matched_count": len(rule.conditions),
            "total_conditions": len(rule.conditions),
            "conclusions": [str(fact) for fact in conclusions],
            "new_facts": [str(fact) for fact in new_facts],
            "mitigation_ids": list(rule.mitigation_ids),
            "reason": (
                f"All {len(rule.conditions)} conditions of "
                f"{rule.rule_id} were present in working memory."
            ),
        })

        return new_facts

    def get_trace(self):
        """Return the inference trace (one entry per rule firing)."""

        return list(self.trace)

    def run(self, max_cycles: int = 100):
        """
        Forward chaining recognize-act cycle.

            1. MATCH    - build the conflict set (fully matched rules)
            2. FILTER   - drop rules that already fired (refractoriness)
            3. SELECT   - conflict resolution picks one rule
            4. ACT      - fire it, asserting conclusions into memory
            5. repeat

        Termination detection:
            "quiescence"  - no unfired rule is fully matched, so no
                            new fact can ever be derived (normal stop)
            "cycle_limit" - safety guard reached max_cycles

        Returns the final working memory.
        """

        self.terminated = False
        self.termination_reason = None

        while True:
            if self.cycles >= max_cycles:
                self.termination_reason = "cycle_limit"
                break

            conflict_set = self.build_conflict_set()

            available_rules = [
                rule
                for rule in conflict_set
                if rule.rule_id not in self.fired_rules
            ]

            if not available_rules:
                self.termination_reason = "quiescence"
                break

            selected_rule = self.select_rule(available_rules)
            self.fire_rule(selected_rule)
            self.cycles += 1

        self.terminated = True
        return self.working_memory.get_all()

    def detected_techniques(self):
        """Rules that fired, in firing order (handy for main.py / Module 4)."""

        return [
            rule
            for entry in self.trace
            for rule in self.knowledge_base.rules
            if rule.rule_id == entry["rule_id"]
        ]