"""
Module 2: Forward Chaining Inference Engine
MITRE ATT&CK Rule-Based Navigator

Owner: Pranathee H
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
    def fire_rule(self, rule: Rule) -> bool:
        """
        Fire a fully matched rule.

        The rule's technique is asserted as a new fact
        in working memory and the firing is recorded
        in the inference trace.
        """

        if not rule.is_fully_matched(
            self.working_memory.facts
        ):
            return False

        conclusion = Fact(
            attribute="technique_detected",
            value=rule.technique_id
        )

        added = self.working_memory.add(conclusion)

        if added:
            self.trace.append({
    "order": len(self.trace) + 1,
    "rule_id": rule.rule_id,
    "technique_id": rule.technique_id,
    "technique_name": rule.technique_name,
    "tactic": rule.tactic,
    "matched_conditions": [
        str(condition)
        for condition in rule.conditions
    ],
    "matched_count": len(rule.conditions),
    "total_conditions": len(rule.conditions),
    "conclusion": str(conclusion),
    "reason": (
        f"All {len(rule.conditions)} conditions of "
        f"{rule.rule_id} were satisfied by the observed facts."
    )
})

        return added
    def get_trace(self):
        """
        Return the inference trace showing
        which rules fired and what they concluded.
        """

        return list(self.trace)
    def run(self):
        """
        Run the forward chaining recognize-act cycle.

        Rules are repeatedly matched and fired until
        no new conclusions can be added to working memory.
        """

        fired_rules = set()
        self.terminated = False

        while True:
            conflict_set = self.build_conflict_set()

            # Remove rules that have already been fired
            available_rules = [
                rule
                for rule in conflict_set
                if rule.rule_id not in fired_rules
            ]

            # No more rules can fire
            if not available_rules:
                self.terminated = True
                break

            # Select the first eligible rule
            selected_rule = available_rules[0]

            # Fire the selected rule
            fired = self.fire_rule(selected_rule)

            if not fired:
                self.terminated = True
                break

            fired_rules.add(selected_rule.rule_id)

        return self.working_memory.get_all()