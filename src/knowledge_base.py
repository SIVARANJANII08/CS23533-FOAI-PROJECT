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

        if not isinstance(text, str) or ":" not in text:
            raise ValueError(
                f"Malformed fact (expected attribute:value): {text}"
            )

        attribute, value = text.split(":", 1)

        if not attribute.strip() or not value.strip():
            raise ValueError(
                f"Malformed fact (attribute/value cannot be empty): {text}"
            )

        return Fact(attribute.strip(), value.strip())

    def __str__(self) -> str:
        return f"{self.attribute}:{self.value}"


@dataclass
class Rule:
    """
    One IF-THEN production rule.

    IF all conditions are present in working memory
    THEN conclude the ATT&CK technique and recommend its mitigations.
    """

    rule_id: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    conditions: List[Fact]
    mitigation_ids: List[str] = field(default_factory=list)

    def matched_conditions(
        self,
        working_memory: Set[Fact]
    ) -> List[Fact]:
        """Return conditions currently satisfied by working memory."""

        return [
            condition
            for condition in self.conditions
            if condition in working_memory
        ]

    def is_fully_matched(
        self,
        working_memory: Set[Fact]
    ) -> bool:
        """Return True when every condition is satisfied."""

        return (
            len(self.matched_conditions(working_memory))
            == len(self.conditions)
        )

    def heuristic(
        self,
        working_memory: Set[Fact]
    ) -> float:
        """
        Module 3 heuristic:
        matched conditions / total conditions.

        Returns a value between 0.0 and 1.0.
        Higher value means stronger evidence.
        """

        if not self.conditions:
            return 0.0

        return (
            len(self.matched_conditions(working_memory))
            / len(self.conditions)
        )

    def __str__(self) -> str:
        return (
            f"[{self.rule_id}] "
            f"{self.technique_id} - "
            f"{self.technique_name}"
        )


class KnowledgeBase:
    """
    Loads and holds all production rules
    plus the mitigation lookup table.
    """

    def __init__(self):
        self.rules: List[Rule] = []
        self.mitigations: Dict[str, dict] = {}

    def load_rules(self, path: str) -> None:
        """Load, validate and convert rules from a JSON file."""

        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        # Validate top-level structure
        if "rules" not in data or not isinstance(data["rules"], list):
            raise ValueError(
                "Invalid knowledge base: 'rules' must be a list."
            )

        seen_ids = set()

        # Required fields for every rule
        required_fields = {
            "rule_id",
            "technique_id",
            "technique_name",
            "tactic",
            "severity",
            "conditions",
        }

        for entry in data["rules"]:

            # Check that the rule is a JSON object
            if not isinstance(entry, dict):
                raise ValueError(
                    "Malformed rule: each rule must be an object."
                )

            # Check required fields
            missing_fields = required_fields - entry.keys()

            if missing_fields:
                raise ValueError(
                    f"Malformed rule: missing fields "
                    f"{sorted(missing_fields)}"
                )

            # Check rule ID
            rule_id = entry["rule_id"]

            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError(
                    "Malformed rule: rule_id must be a non-empty string."
                )

            # Check duplicate rule IDs
            if rule_id in seen_ids:
                raise ValueError(
                    f"Duplicate rule_id: {rule_id}"
                )

            seen_ids.add(rule_id)

            # Check conditions
            conditions = entry["conditions"]

            if not isinstance(conditions, list) or not conditions:
                raise ValueError(
                    f"Malformed rule {rule_id}: "
                    "conditions must be a non-empty list."
                )

            # Convert every condition into a Fact
            fact_conditions = []

            for condition in conditions:

                if not isinstance(condition, str):
                    raise ValueError(
                        f"Malformed condition in {rule_id}: "
                        f"{condition}"
                    )

                fact_conditions.append(
                    Fact.from_string(condition)
                )

            # Create Rule object
            self.rules.append(
                Rule(
                    rule_id=entry["rule_id"],
                    technique_id=entry["technique_id"],
                    technique_name=entry["technique_name"],
                    tactic=entry["tactic"],
                    severity=entry["severity"],
                    conditions=fact_conditions,
                    mitigation_ids=entry.get(
                        "mitigation_ids",
                        []
                    ),
                )
            )

    def load_mitigations(self, path: str) -> None:
        """Load mitigation information from a JSON file."""

        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if (
            "mitigations" not in data
            or not isinstance(data["mitigations"], dict)
        ):
            raise ValueError(
                "Invalid mitigation file: "
                "'mitigations' must be a dictionary."
            )

        self.mitigations = data["mitigations"]

    def get_mitigation(self, mitigation_id: str) -> dict:
        """Return mitigation details for a mitigation ID."""

        return self.mitigations.get(
            mitigation_id,
            {
                "name": "Unknown",
                "description": (
                    "Not found in knowledge base."
                ),
            },
        )

    def tactics(self) -> Set[str]:
        """Return all unique tactics represented in the rules."""

        return {
            rule.tactic
            for rule in self.rules
        }

    def summary(self) -> str:
        """Return a summary of the loaded knowledge base."""

        return (
            f"Loaded {len(self.rules)} rules across "
            f"{len(self.tactics())} tactics and "
            f"{len(self.mitigations)} mitigations."
        )


if __name__ == "__main__":
    kb = KnowledgeBase()

    kb.load_rules("data/rules.json")
    kb.load_mitigations("data/mitigations.json")

    print(kb.summary())

    for rule in kb.rules:
        print(" ", rule)