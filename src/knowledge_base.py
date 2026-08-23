"""
Module 1: Knowledge Base and Fact Representation
MITRE ATT&CK Rule-Based Navigator

Owner: Pranathee H
Defines Fact, Rule, and KnowledgeBase — the foundation every other module builds on.
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass(frozen=True)
class Fact:
    """
    A single observed system behaviour.

    Facts are written as 'attribute:value' strings, e.g.
        process_created:powershell.exe
        failed_login_count_exceeds:5

    frozen=True makes Fact hashable so it can live in a set (working memory).
    """
    attribute: str
    value: str

    @staticmethod
    def from_string(text: str) -> "Fact":
        """Build a Fact from an 'attribute:value' string."""
        if ":" not in text:
            raise ValueError(f"Malformed fact (expected attribute:value): {text}")
        attribute, value = text.split(":", 1)
        return Fact(attribute.strip(), value.strip())

    def __str__(self) -> str:
        return f"{self.attribute}:{self.value}"


@dataclass
class Rule:
    """
    One IF-THEN production rule.

    IF  all conditions are present in working memory
    THEN conclude the ATT&CK technique and recommend its mitigations.
    """
    rule_id: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    conditions: List[Fact]
    mitigation_ids: List[str] = field(default_factory=list)

    def matched_conditions(self, working_memory: Set[Fact]) -> List[Fact]:
        """Conditions currently satisfied by working memory."""
        return [c for c in self.conditions if c in working_memory]

    def is_fully_matched(self, working_memory: Set[Fact]) -> bool:
        """True when every condition is satisfied — the rule can fire."""
        return len(self.matched_conditions(working_memory)) == len(self.conditions)

    def heuristic(self, working_memory: Set[Fact]) -> float:
        """
        Module 3 heuristic: matched conditions / total conditions.
        Returns 0.0 to 1.0. Higher means better supported by evidence.
        """
        if not self.conditions:
            return 0.0
        return len(self.matched_conditions(working_memory)) / len(self.conditions)

    def __str__(self) -> str:
        return f"[{self.rule_id}] {self.technique_id} - {self.technique_name}"


class KnowledgeBase:
    """Loads and holds all production rules plus the mitigation lookup table."""

    def __init__(self):
        self.rules: List[Rule] = []
        self.mitigations: Dict[str, dict] = {}

    def load_rules(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        seen_ids = set()
        for entry in data["rules"]:
            if entry["rule_id"] in seen_ids:
                raise ValueError(f"Duplicate rule_id: {entry['rule_id']}")
            seen_ids.add(entry["rule_id"])

            self.rules.append(Rule(
                rule_id=entry["rule_id"],
                technique_id=entry["technique_id"],
                technique_name=entry["technique_name"],
                tactic=entry["tactic"],
                severity=entry["severity"],
                conditions=[Fact.from_string(c) for c in entry["conditions"]],
                mitigation_ids=entry.get("mitigation_ids", []),
            ))

    def load_mitigations(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            self.mitigations = json.load(f)["mitigations"]

    def get_mitigation(self, mitigation_id: str) -> dict:
        return self.mitigations.get(
            mitigation_id, {"name": "Unknown", "description": "Not found in knowledge base."}
        )

    def tactics(self) -> Set[str]:
        return {r.tactic for r in self.rules}

    def summary(self) -> str:
        return (f"Loaded {len(self.rules)} rules across {len(self.tactics())} tactics "
                f"and {len(self.mitigations)} mitigations.")


if __name__ == "__main__":
    kb = KnowledgeBase()
    kb.load_rules("data/rules.json")
    kb.load_mitigations("data/mitigations.json")
    print(kb.summary())
    for rule in kb.rules:
        print(" ", rule)
